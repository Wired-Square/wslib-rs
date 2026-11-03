//! A board definition to edit, from a [`BoardDef`] or TOML, written back as
//! TOML.

use std::collections::{BTreeMap, HashSet};
use std::path::Path;

use toml_edit::{DocumentMut, Item, Table};
use wslib_framelink_protocol::dsig::{SignalKey, format_signal_key, parse_signal_key};

use crate::toml_schema::{self, BoardFile, parse_hex_key};
use crate::{BoardDef, Error, FrameDefDisplayInfo};

/// Every map is a [`BTreeMap`], so the TOML it writes is sorted.
#[derive(Debug, Clone)]
pub struct EditableBoardDef {
    pub name: String,
    pub revision: String,
    pub description: String,
    pub interfaces: BTreeMap<u8, EditableInterface>,
    pub peripherals: BTreeMap<u8, EditablePeripheral>,
    pub signals: BTreeMap<SignalKey, EditableSignal>,
    /// User signals have no tuple, so they are keyed by id.
    pub user_signals: BTreeMap<u16, EditableSignal>,
    pub frame_defs: BTreeMap<u16, EditableFrameDef>,
    pub generators: BTreeMap<u16, EditableGenerator>,
    pub transformers: BTreeMap<u16, EditableTransformer>,
    pub dirty: bool,
    pub pending: PendingLabels,

    /// Not edited here, so written back as read.
    passthrough_palettes: Option<toml_edit::Item>,
    passthrough_functions: Option<toml_edit::Item>,
}

#[derive(Debug, Clone)]
pub struct EditableInterface {
    pub name: String,
    pub iface_type: String,
    pub description: String,
}

#[derive(Debug, Clone)]
pub struct EditablePeripheral {
    pub name: String,
    pub kind: String,
    pub description: String,
}

#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
pub struct EditableSignal {
    pub name: String,
    pub description: String,
    pub group: String,
    pub unit: String,
    pub format: String,
    pub enum_values: BTreeMap<u32, String>,
}

#[derive(Debug, Clone)]
pub struct EditableFrameDef {
    pub name: String,
    pub description: String,
    pub interface_type: String,
    pub can: Option<EditableCanHeader>,
    pub rs485: Option<EditableRs485Header>,
    pub signals: Vec<EditableFrameSignal>,
}

#[derive(Debug, Clone)]
pub struct EditableCanHeader {
    pub can_id: u32,
    pub dlc: u8,
    pub flags: Vec<String>,
}

#[derive(Debug, Clone)]
pub struct EditableRs485Header {
    pub framing_mode: String,
}

#[derive(Debug, Clone)]
pub struct EditableFrameSignal {
    pub slug: String,
    pub name: String,
    pub start_bit: u16,
    pub bit_length: u16,
    pub byte_order: String,
    pub value_type: String,
    pub quantity: u8,
    pub scale: f32,
    pub offset: f32,
    pub unit: String,
}

#[derive(Debug, Clone)]
pub struct EditableGenerator {
    pub name: String,
    pub description: String,
}

#[derive(Debug, Clone)]
pub struct EditableTransformer {
    pub name: String,
    pub description: String,
}

/// Labels for rules not yet on the device; displayed, never written to the
/// board TOML.
#[derive(Debug, Clone, Default)]
pub struct PendingLabels {
    pub frame_defs: BTreeMap<u16, PendingLabel>,
    pub generators: BTreeMap<u16, PendingLabel>,
    pub transformers: BTreeMap<u16, PendingLabel>,
}

/// `None` keeps what is there.
#[derive(Debug, Clone, Default)]
pub struct PendingLabel {
    pub name: Option<String>,
    pub description: Option<String>,
}

/// The rule ids a device holds, for [`EditableBoardDef::merge_pending`].
pub struct ActiveRuleIds {
    pub frame_defs: HashSet<u16>,
    pub generators: HashSet<u16>,
    pub transformers: HashSet<u16>,
}

impl EditableBoardDef {
    pub fn new_empty() -> Self {
        Self {
            name: String::new(),
            revision: String::new(),
            description: String::new(),
            interfaces: BTreeMap::new(),
            peripherals: BTreeMap::new(),
            signals: BTreeMap::new(),
            user_signals: BTreeMap::new(),
            frame_defs: BTreeMap::new(),
            generators: BTreeMap::new(),
            transformers: BTreeMap::new(),
            dirty: false,
            pending: PendingLabels::default(),
            passthrough_palettes: None,
            passthrough_functions: None,
        }
    }

    /// A [`BoardDef`] keeps no CAN or RS-485 headers, so neither has any.
    pub fn from_board_def(bd: &BoardDef) -> Self {
        let mut interfaces = BTreeMap::new();
        for (&idx, info) in &bd.interfaces {
            interfaces.insert(
                idx,
                EditableInterface {
                    name: info.name.clone(),
                    iface_type: info.iface_type.clone(),
                    description: info.description.clone(),
                },
            );
        }

        let mut peripherals = BTreeMap::new();
        for (&idx, info) in &bd.peripherals {
            peripherals.insert(
                idx,
                EditablePeripheral {
                    name: info.name.clone(),
                    kind: info.kind.clone(),
                    description: info.description.clone(),
                },
            );
        }

        let mut signals = BTreeMap::new();
        for (&key, info) in &bd.signals {
            signals.insert(
                key,
                EditableSignal {
                    name: info.name.clone(),
                    description: info.description.clone(),
                    group: info.group.clone(),
                    unit: info.unit.clone(),
                    format: info.format.clone(),
                    enum_values: info
                        .enum_values
                        .iter()
                        .map(|(&k, v)| (k, v.clone()))
                        .collect(),
                },
            );
        }

        let user_signals: BTreeMap<u16, EditableSignal> = bd
            .user_signals
            .iter()
            .map(|(&id, info)| {
                (
                    id,
                    EditableSignal {
                        name: info.name.clone(),
                        description: info.description.clone(),
                        group: info.group.clone(),
                        unit: info.unit.clone(),
                        format: info.format.clone(),
                        enum_values: info
                            .enum_values
                            .iter()
                            .map(|(&k, v)| (k, v.clone()))
                            .collect(),
                    },
                )
            })
            .collect();

        let mut frame_defs = BTreeMap::new();
        for (&id, info) in &bd.frame_defs {
            frame_defs.insert(id, editable_frame_def_from_display(info));
        }

        let mut generators = BTreeMap::new();
        for (&id, info) in &bd.generators {
            generators.insert(
                id,
                EditableGenerator {
                    name: info.name.clone(),
                    description: info.description.clone(),
                },
            );
        }

        let mut transformers = BTreeMap::new();
        for (&id, info) in &bd.transformers {
            transformers.insert(
                id,
                EditableTransformer {
                    name: info.name.clone(),
                    description: info.description.clone(),
                },
            );
        }

        EditableBoardDef {
            name: bd.name.clone(),
            revision: bd.revision.clone(),
            description: bd.description.clone(),
            interfaces,
            peripherals,
            signals,
            user_signals,
            frame_defs,
            generators,
            transformers,
            dirty: false,
            pending: PendingLabels::default(),
            passthrough_palettes: None,
            passthrough_functions: None,
        }
    }

    pub fn to_board_def(&self) -> Result<BoardDef, Error> {
        crate::parse_board_def(&self.to_toml())
    }

    pub fn from_toml(toml_str: &str) -> Result<Self, Error> {
        let raw_doc: DocumentMut = toml_str.parse()?;
        let passthrough_palettes = raw_doc.get("palettes").cloned();
        let passthrough_functions = raw_doc.get("functions").cloned();
        let file: BoardFile = toml_edit::de::from_document(raw_doc)?;

        let mut interfaces = BTreeMap::new();
        for (key, def) in file.interfaces {
            interfaces.insert(
                key.parse().map_err(|source| Error::Key {
                    section: "interface",
                    key,
                    source,
                })?,
                EditableInterface {
                    name: def.name,
                    iface_type: def.iface_type,
                    description: def.description,
                },
            );
        }

        let mut peripherals = BTreeMap::new();
        for (key, def) in file.peripherals {
            peripherals.insert(
                key.parse().map_err(|source| Error::Key {
                    section: "peripheral",
                    key,
                    source,
                })?,
                EditablePeripheral {
                    name: def.name,
                    kind: def.kind,
                    description: def.description,
                },
            );
        }

        let mut signals = BTreeMap::new();
        for (key, def) in file.signals {
            let sig_key = parse_signal_key(&key)?;
            let enum_values: BTreeMap<u32, String> = def
                .enum_values
                .into_iter()
                .filter_map(|(k, v)| k.parse::<u32>().ok().map(|n| (n, v)))
                .collect();
            signals.insert(
                sig_key,
                EditableSignal {
                    name: def.name,
                    description: def.description,
                    group: def.group,
                    unit: def.unit,
                    format: def.format,
                    enum_values,
                },
            );
        }

        let mut user_signals = BTreeMap::new();
        for (key, def) in file.user_signals {
            let id = hex_key("user_signal", &key)?;
            let enum_values: BTreeMap<u32, String> = def
                .enum_values
                .into_iter()
                .filter_map(|(k, v)| k.parse::<u32>().ok().map(|n| (n, v)))
                .collect();
            user_signals.insert(
                id,
                EditableSignal {
                    name: def.name,
                    description: def.description,
                    group: def.group,
                    unit: def.unit,
                    format: def.format,
                    enum_values,
                },
            );
        }

        let mut frame_defs = BTreeMap::new();
        for (key, def) in file.frame_defs {
            let id = hex_key("frame_def", &key)?;
            frame_defs.insert(id, editable_frame_def_from_toml(def));
        }

        let mut generators = BTreeMap::new();
        for (key, def) in file.generators {
            let id = hex_key("generator", &key)?;
            generators.insert(
                id,
                EditableGenerator {
                    name: def.name,
                    description: def.description,
                },
            );
        }

        let mut transformers = BTreeMap::new();
        for (key, def) in file.transformers {
            let id = hex_key("transformer", &key)?;
            transformers.insert(
                id,
                EditableTransformer {
                    name: def.name,
                    description: def.description,
                },
            );
        }

        Ok(EditableBoardDef {
            name: file.board.name,
            revision: file.board.revision,
            description: file.board.description,
            interfaces,
            peripherals,
            signals,
            user_signals,
            frame_defs,
            generators,
            transformers,
            dirty: false,
            pending: PendingLabels::default(),
            passthrough_palettes,
            passthrough_functions,
        })
    }

    pub fn to_toml(&self) -> String {
        use toml_edit::Array;

        let mut doc = DocumentMut::new();

        doc.decor_mut().set_prefix(format!(
            "# Board definition: {} ({})\n\n",
            self.name, self.revision,
        ));

        let mut board = Table::new();
        board.insert("name", toml_edit::value(&self.name));
        board.insert("revision", toml_edit::value(&self.revision));
        board.insert("description", toml_edit::value(&self.description));
        doc.insert("board", Item::Table(board));

        if !self.interfaces.is_empty() {
            let mut ifaces = section("Interface definitions");
            for (&idx, iface) in &self.interfaces {
                let mut t = Table::new();
                t.insert("name", toml_edit::value(&iface.name));
                t.insert("type", toml_edit::value(&iface.iface_type));
                if !iface.description.is_empty() {
                    t.insert("description", toml_edit::value(&iface.description));
                }
                ifaces.insert(&idx.to_string(), Item::Table(t));
            }
            doc.insert("interfaces", Item::Table(ifaces));
        }

        if !self.peripherals.is_empty() {
            let mut periphs = section("Peripheral definitions");
            for (&idx, periph) in &self.peripherals {
                let mut t = Table::new();
                t.insert("name", toml_edit::value(&periph.name));
                t.insert("kind", toml_edit::value(&periph.kind));
                if !periph.description.is_empty() {
                    t.insert("description", toml_edit::value(&periph.description));
                }
                periphs.insert(&idx.to_string(), Item::Table(t));
            }
            doc.insert("peripherals", Item::Table(periphs));
        }

        if !self.signals.is_empty() {
            let mut sigs = section("Signal definitions");
            for (key, sig) in &self.signals {
                sigs.insert(&format_signal_key(key), Item::Table(signal_table(sig)));
            }
            doc.insert("signals", Item::Table(sigs));
        }

        if !self.user_signals.is_empty() {
            let mut sigs = section("User signal definitions (display labels, keyed by signal id)");
            for (&id, sig) in &self.user_signals {
                sigs.insert(&hex(id), Item::Table(signal_table(sig)));
            }
            doc.insert("user_signals", Item::Table(sigs));
        }

        if !self.frame_defs.is_empty() {
            let mut fdefs = section("Frame definitions");
            for (&id, fdef) in &self.frame_defs {
                let hex_key = hex(id);
                let mut t = Table::new();
                t.insert("name", toml_edit::value(&fdef.name));
                if !fdef.description.is_empty() {
                    t.insert("description", toml_edit::value(&fdef.description));
                }
                if !fdef.interface_type.is_empty() {
                    t.insert("interface_type", toml_edit::value(&fdef.interface_type));
                }

                if let Some(can) = &fdef.can {
                    let mut ct = Table::new();
                    ct.insert("can_id", toml_edit::value(i64::from(can.can_id)));
                    ct.insert("dlc", toml_edit::value(i64::from(can.dlc)));
                    if !can.flags.is_empty() {
                        let mut arr = Array::new();
                        for flag in &can.flags {
                            arr.push(flag.as_str());
                        }
                        ct.insert("flags", toml_edit::value(arr));
                    } else {
                        ct.insert("flags", toml_edit::value(Array::new()));
                    }
                    t.insert("can", Item::Table(ct));
                }

                if let Some(rs) = &fdef.rs485 {
                    let mut rt = Table::new();
                    if !rs.framing_mode.is_empty() {
                        rt.insert("framing_mode", toml_edit::value(&rs.framing_mode));
                    }
                    t.insert("rs485", Item::Table(rt));
                }

                if !fdef.signals.is_empty() {
                    let mut sig_table = Table::new();
                    for sig in &fdef.signals {
                        let mut st = Table::new();
                        st.insert("name", toml_edit::value(&sig.name));
                        st.insert(
                            "bits",
                            toml_edit::value(format!("{}:{}", sig.start_bit, sig.bit_length)),
                        );
                        st.insert("byte_order", toml_edit::value(&sig.byte_order));
                        st.insert("value_type", toml_edit::value(&sig.value_type));
                        if let Some(quantity) = toml_schema::quantity_to_toml(sig.quantity) {
                            st.insert("quantity", toml_edit::value(quantity));
                        }
                        st.insert("scale", toml_edit::value(f64::from(sig.scale)));
                        st.insert("offset", toml_edit::value(f64::from(sig.offset)));
                        if !sig.unit.is_empty() {
                            st.insert("unit", toml_edit::value(&sig.unit));
                        }
                        sig_table.insert(&sig.slug, Item::Table(st));
                    }
                    t.insert("signals", Item::Table(sig_table));
                }

                fdefs.insert(&hex_key, Item::Table(t));
            }
            doc.insert("frame_defs", Item::Table(fdefs));
        }

        if !self.generators.is_empty() {
            let mut gens = section("Generator labels");
            for (&id, gdef) in &self.generators {
                let hex_key = hex(id);
                let mut t = Table::new();
                t.insert("name", toml_edit::value(&gdef.name));
                if !gdef.description.is_empty() {
                    t.insert("description", toml_edit::value(&gdef.description));
                }
                gens.insert(&hex_key, Item::Table(t));
            }
            doc.insert("generators", Item::Table(gens));
        }

        if !self.transformers.is_empty() {
            let mut xforms = section("Transformer labels");
            for (&id, xdef) in &self.transformers {
                let hex_key = hex(id);
                let mut t = Table::new();
                t.insert("name", toml_edit::value(&xdef.name));
                if !xdef.description.is_empty() {
                    t.insert("description", toml_edit::value(&xdef.description));
                }
                xforms.insert(&hex_key, Item::Table(t));
            }
            doc.insert("transformers", Item::Table(xforms));
        }

        if let Some(palettes) = &self.passthrough_palettes {
            doc["palettes"] = palettes.clone();
        }
        if let Some(functions) = &self.passthrough_functions {
            doc["functions"] = functions.clone();
        }

        doc.to_string()
    }

    /// Merges into any pending label: a `None` keeps what is there. A pending
    /// label does not make the definition dirty.
    pub fn set_pending_frame_def(
        &mut self,
        id: u16,
        name: Option<String>,
        description: Option<String>,
    ) {
        set_pending(&mut self.pending.frame_defs, id, name, description);
    }

    pub fn remove_pending_frame_def(&mut self, id: u16) {
        self.pending.frame_defs.remove(&id);
    }

    pub fn set_pending_generator(
        &mut self,
        id: u16,
        name: Option<String>,
        description: Option<String>,
    ) {
        set_pending(&mut self.pending.generators, id, name, description);
    }

    pub fn remove_pending_generator(&mut self, id: u16) {
        self.pending.generators.remove(&id);
    }

    pub fn set_pending_transformer(
        &mut self,
        id: u16,
        name: Option<String>,
        description: Option<String>,
    ) {
        set_pending(&mut self.pending.transformers, id, name, description);
    }

    pub fn remove_pending_transformer(&mut self, id: u16) {
        self.pending.transformers.remove(&id);
    }

    /// The pending name, else the committed one, else `"Frame 0xNNNN"`.
    pub fn resolve_frame_def_name(&self, id: u16) -> String {
        resolve_name(
            &self.pending.frame_defs,
            self.frame_defs.get(&id).map(|f| &f.name),
            id,
            "Frame",
        )
    }

    /// The pending description, else a non-empty committed one.
    pub fn resolve_frame_def_description(&self, id: u16) -> Option<String> {
        resolve_description(
            &self.pending.frame_defs,
            self.frame_defs.get(&id).map(|f| &f.description),
            id,
        )
    }

    pub fn resolve_generator_name(&self, id: u16) -> String {
        resolve_name(
            &self.pending.generators,
            self.generators.get(&id).map(|g| &g.name),
            id,
            "Generator",
        )
    }

    pub fn resolve_generator_description(&self, id: u16) -> Option<String> {
        resolve_description(
            &self.pending.generators,
            self.generators.get(&id).map(|g| &g.description),
            id,
        )
    }

    pub fn resolve_transformer_name(&self, id: u16) -> String {
        resolve_name(
            &self.pending.transformers,
            self.transformers.get(&id).map(|t| &t.name),
            id,
            "Transformer",
        )
    }

    pub fn resolve_transformer_description(&self, id: u16) -> Option<String> {
        resolve_description(
            &self.pending.transformers,
            self.transformers.get(&id).map(|t| &t.description),
            id,
        )
    }

    /// Writes the pending labels to `{device_id}.pending.toml` in `cache_dir`,
    /// or removes that file when there are none.
    pub fn save_pending(&self, cache_dir: &Path, device_id: &str) -> Result<(), Error> {
        let path = cache_dir.join(format!("{device_id}.pending.toml"));
        let sections = [
            ("frame_defs", &self.pending.frame_defs),
            ("generators", &self.pending.generators),
            ("transformers", &self.pending.transformers),
        ];
        if sections.iter().all(|(_, labels)| labels.is_empty()) {
            let _ = std::fs::remove_file(&path);
            return Ok(());
        }

        let mut doc = DocumentMut::new();
        for (name, labels) in sections {
            if !labels.is_empty() {
                doc.insert(name, Item::Table(labels_table(labels)));
            }
        }
        std::fs::create_dir_all(cache_dir)?;
        Ok(std::fs::write(&path, doc.to_string())?)
    }

    /// Reads what [`save_pending`](Self::save_pending) wrote; no file is no
    /// labels.
    pub fn load_pending(&mut self, cache_dir: &Path, device_id: &str) -> Result<(), Error> {
        let path = cache_dir.join(format!("{device_id}.pending.toml"));
        if !path.exists() {
            return Ok(());
        }
        let doc: DocumentMut = std::fs::read_to_string(&path)?.parse()?;
        read_labels(&doc, "frame_defs", &mut self.pending.frame_defs)?;
        read_labels(&doc, "generators", &mut self.pending.generators)?;
        read_labels(&doc, "transformers", &mut self.pending.transformers)
    }

    /// Commits the pending labels of the rules the device holds, and drops
    /// the rest.
    pub fn merge_pending(&mut self, active: &ActiveRuleIds) {
        for (id, label) in std::mem::take(&mut self.pending.frame_defs) {
            if active.frame_defs.contains(&id) {
                let entry = self
                    .frame_defs
                    .entry(id)
                    .or_insert_with(|| EditableFrameDef {
                        name: format!("Frame 0x{id:04X}"),
                        description: String::new(),
                        interface_type: String::new(),
                        can: None,
                        rs485: None,
                        signals: Vec::new(),
                    });
                label.apply(&mut entry.name, &mut entry.description);
            }
        }
        for (id, label) in std::mem::take(&mut self.pending.generators) {
            if active.generators.contains(&id) {
                let entry = self
                    .generators
                    .entry(id)
                    .or_insert_with(|| EditableGenerator {
                        name: format!("Generator 0x{id:04X}"),
                        description: String::new(),
                    });
                label.apply(&mut entry.name, &mut entry.description);
            }
        }
        for (id, label) in std::mem::take(&mut self.pending.transformers) {
            if active.transformers.contains(&id) {
                let entry = self
                    .transformers
                    .entry(id)
                    .or_insert_with(|| EditableTransformer {
                        name: format!("Transformer 0x{id:04X}"),
                        description: String::new(),
                    });
                label.apply(&mut entry.name, &mut entry.description);
            }
        }
    }
}

impl PendingLabel {
    fn apply(self, name: &mut String, description: &mut String) {
        if let Some(n) = self.name {
            *name = n;
        }
        if let Some(d) = self.description {
            *description = d;
        }
    }
}

fn set_pending(
    labels: &mut BTreeMap<u16, PendingLabel>,
    id: u16,
    name: Option<String>,
    description: Option<String>,
) {
    let entry = labels.entry(id).or_default();
    if name.is_some() {
        entry.name = name;
    }
    if description.is_some() {
        entry.description = description;
    }
}

fn resolve_name(
    pending: &BTreeMap<u16, PendingLabel>,
    committed: Option<&String>,
    id: u16,
    kind: &str,
) -> String {
    pending
        .get(&id)
        .and_then(|p| p.name.clone())
        .or_else(|| committed.cloned())
        .unwrap_or_else(|| format!("{kind} 0x{id:04X}"))
}

fn resolve_description(
    pending: &BTreeMap<u16, PendingLabel>,
    committed: Option<&String>,
    id: u16,
) -> Option<String> {
    pending
        .get(&id)
        .and_then(|p| p.description.clone())
        .or_else(|| committed.filter(|d| !d.is_empty()).cloned())
}

fn labels_table(labels: &BTreeMap<u16, PendingLabel>) -> Table {
    let mut section = Table::new();
    for (&id, label) in labels {
        let mut t = Table::new();
        if let Some(name) = &label.name {
            t.insert("name", toml_edit::value(name));
        }
        if let Some(desc) = &label.description {
            t.insert("description", toml_edit::value(desc));
        }
        section.insert(&hex(id), Item::Table(t));
    }
    section
}

fn read_labels(
    doc: &DocumentMut,
    section: &'static str,
    into: &mut BTreeMap<u16, PendingLabel>,
) -> Result<(), Error> {
    let Some(table) = doc.get(section).and_then(|v| v.as_table()) else {
        return Ok(());
    };
    for (key, item) in table {
        let id = hex_key(section, key)?;
        let tbl = item.as_table().ok_or_else(|| Error::NotATable {
            section,
            key: key.to_string(),
        })?;
        let text = |field| tbl.get(field).and_then(|v| v.as_str()).map(String::from);
        into.insert(
            id,
            PendingLabel {
                name: text("name"),
                description: text("description"),
            },
        );
    }
    Ok(())
}

fn hex(id: u16) -> String {
    format!("0x{id:04X}")
}

fn hex_key(section: &'static str, key: &str) -> Result<u16, Error> {
    parse_hex_key(key).map_err(|source| Error::Key {
        section,
        key: key.to_string(),
        source,
    })
}

fn section(title: &str) -> Table {
    let rule = "# -----------------------------------------------------------------------";
    let mut table = Table::new();
    table
        .decor_mut()
        .set_prefix(format!("\n{rule}\n# {title}\n{rule}\n\n"));
    table
}

fn signal_table(sig: &EditableSignal) -> Table {
    let mut t = Table::new();
    t.insert("name", toml_edit::value(&sig.name));
    for (field, text) in [
        ("description", &sig.description),
        ("group", &sig.group),
        ("unit", &sig.unit),
        ("format", &sig.format),
    ] {
        if !text.is_empty() {
            t.insert(field, toml_edit::value(text));
        }
    }
    if !sig.enum_values.is_empty() {
        let mut enum_table = Table::new();
        for (&val, label) in &sig.enum_values {
            enum_table.insert(&val.to_string(), toml_edit::value(label));
        }
        t.insert("enum", Item::Table(enum_table));
    }
    t
}

/// A display definition carries no CAN or RS-485 header.
fn editable_frame_def_from_display(info: &FrameDefDisplayInfo) -> EditableFrameDef {
    let signals = info
        .signals
        .iter()
        .map(|s| EditableFrameSignal {
            slug: s.slug.clone(),
            name: s.name.clone(),
            start_bit: s.start_bit,
            bit_length: s.bit_length,
            byte_order: s.byte_order.clone(),
            value_type: s.value_type.clone(),
            quantity: s.quantity,
            scale: s.scale,
            offset: s.offset,
            unit: s.unit.clone(),
        })
        .collect();

    EditableFrameDef {
        name: info.name.clone(),
        description: info.description.clone(),
        interface_type: info.interface_type.clone(),
        can: None,
        rs485: None,
        signals,
    }
}

fn editable_frame_def_from_toml(def: toml_schema::FrameDefDef) -> EditableFrameDef {
    let can = def.can.map(|c| EditableCanHeader {
        can_id: c.can_id,
        dlc: c.dlc,
        flags: c.flags,
    });

    let rs485 = def.rs485.map(|r| EditableRs485Header {
        framing_mode: r.framing_mode,
    });

    let mut signals: Vec<EditableFrameSignal> = def
        .signals
        .into_iter()
        .filter_map(|(slug, sig)| {
            let parts: Vec<&str> = sig.bits.split(':').collect();
            if parts.len() != 2 {
                return None;
            }
            let start = parts[0].parse::<u16>().ok()?;
            let len = parts[1].parse::<u16>().ok()?;
            Some(EditableFrameSignal {
                slug,
                name: sig.name,
                start_bit: start,
                bit_length: len,
                byte_order: sig.byte_order,
                value_type: sig.value_type,
                quantity: sig.quantity,
                scale: sig.scale,
                offset: sig.offset,
                unit: sig.unit,
            })
        })
        .collect();

    signals.sort_by_key(|s| s.start_bit);

    EditableFrameDef {
        name: def.name,
        description: def.description,
        interface_type: def.interface_type,
        can,
        rs485,
        signals,
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::collections::HashSet;
    use wslib_framelink_protocol::types;

    #[test]
    fn user_signals_round_trip_through_toml() {
        let mut ed =
            EditableBoardDef::from_toml("[board]\nname = \"t\"\nrevision = \"a\"\n").unwrap();
        ed.user_signals.insert(
            0x0200,
            EditableSignal {
                name: "Battery SOC".to_string(),
                description: String::new(),
                group: "User".to_string(),
                unit: "%".to_string(),
                format: "number".to_string(),
                enum_values: BTreeMap::new(),
            },
        );

        let toml = ed.to_toml();
        assert!(toml.contains("[user_signals.0x0200]"), "toml was:\n{toml}");

        let reparsed = EditableBoardDef::from_toml(&toml).unwrap();
        let got = reparsed
            .user_signals
            .get(&0x0200)
            .expect("user signal present");
        assert_eq!(got.name, "Battery SOC");
        assert_eq!(got.unit, "%");
    }

    #[test]
    fn to_board_def_carries_user_signal_labels() {
        let mut ed =
            EditableBoardDef::from_toml("[board]\nname = \"t\"\nrevision = \"a\"\n").unwrap();
        ed.user_signals.insert(
            0x0200,
            EditableSignal {
                name: "Battery SOC".to_string(),
                description: String::new(),
                group: "Pack".to_string(),
                unit: "%".to_string(),
                format: "number".to_string(),
                enum_values: BTreeMap::new(),
            },
        );
        let bd = ed.to_board_def().unwrap();
        assert_eq!(bd.user_signal_info(0x0200).unwrap().name, "Battery SOC");
    }

    const TEST_TOML: &str = r#"
[board]
name = "testboard"
revision = "v1.0"
description = "Test board"

[interfaces.0]
name = "CAN0"
type = "can"
description = "Primary CAN bus"

[interfaces.1]
name = "RS0"
type = "rs485"

[peripherals.0]
name = "Status LEDs"
kind = "actuator"

[signals."interface.0.config.datarate"]
name = "CAN0 Bitrate"
group = "CAN0"
unit = "bps"
format = "number"

[signals."peripheral.0.setpoint.enum.ch0"]
name = "LED State"
group = "LEDs"
format = "enum"
[signals."peripheral.0.setpoint.enum.ch0".enum]
0 = "Off"
1 = "On"
2 = "Blink"

[frame_defs.0x0001]
name = "Engine Status"
interface_type = "can"

[frame_defs.0x0001.can]
can_id = 256
dlc = 8
flags = []

[frame_defs.0x0001.signals.engine_rpm]
name = "Engine RPM"
bits = "0:16"
byte_order = "le"
value_type = "unsigned"
scale = 1.0
offset = 0.0
unit = "rpm"

[generators.0x0010]
name = "Status Broadcast"
description = "Broadcasts engine status every 100ms"

[transformers.0x0020]
name = "CAN to LEDs"
description = "Maps CAN signals to LED indicators"
"#;

    #[test]
    fn from_toml_parses_board_metadata() {
        let ed = EditableBoardDef::from_toml(TEST_TOML).unwrap();
        assert_eq!(ed.name, "testboard");
        assert_eq!(ed.revision, "v1.0");
        assert_eq!(ed.description, "Test board");
        assert!(!ed.dirty);
    }

    #[test]
    fn from_toml_parses_interfaces_and_peripherals() {
        let ed = EditableBoardDef::from_toml(TEST_TOML).unwrap();
        assert_eq!(ed.interfaces.len(), 2);
        assert_eq!(ed.interfaces[&0].name, "CAN0");
        assert_eq!(ed.interfaces[&0].iface_type, "can");
        assert_eq!(ed.interfaces[&1].name, "RS0");
        assert_eq!(ed.peripherals.len(), 1);
        assert_eq!(ed.peripherals[&0].kind, "actuator");
    }

    fn bitrate_key() -> SignalKey {
        parse_signal_key("interface.0.config.datarate").unwrap()
    }

    fn led_state_key() -> SignalKey {
        parse_signal_key("peripheral.0.setpoint.enum.ch0").unwrap()
    }

    #[test]
    fn from_toml_parses_signals_with_enums() {
        let ed = EditableBoardDef::from_toml(TEST_TOML).unwrap();
        assert_eq!(ed.signals.len(), 2);
        let bitrate = &ed.signals[&bitrate_key()];
        assert_eq!(bitrate.name, "CAN0 Bitrate");
        assert_eq!(bitrate.unit, "bps");

        let led_state = &ed.signals[&led_state_key()];
        assert_eq!(led_state.format, "enum");
        assert_eq!(led_state.enum_values.len(), 3);
        assert_eq!(led_state.enum_values[&0], "Off");
        assert_eq!(led_state.enum_values[&2], "Blink");
    }

    #[test]
    fn from_toml_parses_frame_defs_with_can_header() {
        let ed = EditableBoardDef::from_toml(TEST_TOML).unwrap();
        assert_eq!(ed.frame_defs.len(), 1);
        let fdef = &ed.frame_defs[&0x0001];
        assert_eq!(fdef.name, "Engine Status");
        assert_eq!(fdef.interface_type, "can");

        let can = fdef.can.as_ref().unwrap();
        assert_eq!(can.can_id, 256);
        assert_eq!(can.dlc, 8);

        assert_eq!(fdef.signals.len(), 1);
        let sig = &fdef.signals[0];
        assert_eq!(sig.slug, "engine_rpm");
        assert_eq!(sig.start_bit, 0);
        assert_eq!(sig.bit_length, 16);
        assert_eq!(sig.unit, "rpm");
    }

    #[test]
    fn a_frame_signal_quantity_round_trips_and_raw_is_left_out() {
        let rated = TEST_TOML.replace(
            "unit = \"rpm\"",
            "unit = \"rpm\"\nquantity = \"temperature_per_s\"",
        );
        let ed = EditableBoardDef::from_toml(&rated).unwrap();
        assert_eq!(
            ed.frame_defs[&0x0001].signals[0].quantity,
            types::QTY_TEMPERATURE | types::QTY_PER_SECOND
        );
        let written = ed.to_toml();
        assert!(
            written.contains("quantity = \"temperature_per_s\""),
            "{written}"
        );
        assert_eq!(
            EditableBoardDef::from_toml(&written).unwrap().frame_defs[&0x0001].signals[0].quantity,
            types::QTY_TEMPERATURE | types::QTY_PER_SECOND
        );

        let raw = EditableBoardDef::from_toml(TEST_TOML).unwrap();
        assert_eq!(raw.frame_defs[&0x0001].signals[0].quantity, types::QTY_RAW);
        assert!(!raw.to_toml().contains("quantity ="));
    }

    #[test]
    fn an_unnamed_frame_signal_quantity_loads_from_hex_and_decimal_is_refused() {
        let hex = TEST_TOML.replace("unit = \"rpm\"", "unit = \"rpm\"\nquantity = \"0x96\"");
        let ed = EditableBoardDef::from_toml(&hex).unwrap();
        assert_eq!(ed.frame_defs[&0x0001].signals[0].quantity, 0x96);
        assert!(ed.to_toml().contains("quantity = \"0x96\""));

        let decimal = TEST_TOML.replace("unit = \"rpm\"", "unit = \"rpm\"\nquantity = \"22\"");
        let error = EditableBoardDef::from_toml(&decimal)
            .unwrap_err()
            .to_string();
        assert!(error.contains("unknown quantity '22'"), "{error}");
    }

    #[test]
    fn an_unknown_frame_signal_quantity_is_refused() {
        let unknown = TEST_TOML.replace("unit = \"rpm\"", "unit = \"rpm\"\nquantity = \"warmth\"");
        let error = EditableBoardDef::from_toml(&unknown)
            .unwrap_err()
            .to_string();
        assert!(error.contains("unknown quantity 'warmth'"), "{error}");
    }

    #[test]
    fn round_trip_toml() {
        let ed = EditableBoardDef::from_toml(TEST_TOML).unwrap();
        let output = ed.to_toml();

        let ed2 = EditableBoardDef::from_toml(&output).unwrap();
        assert_eq!(ed2.name, ed.name);
        assert_eq!(ed2.revision, ed.revision);
        assert_eq!(ed2.interfaces.len(), ed.interfaces.len());
        assert_eq!(ed2.signals.len(), ed.signals.len());
        assert_eq!(ed2.frame_defs.len(), ed.frame_defs.len());

        let fdef = &ed2.frame_defs[&0x0001];
        assert!(fdef.can.is_some());
        assert_eq!(fdef.can.as_ref().unwrap().can_id, 256);

        assert_eq!(ed2.generators.len(), ed.generators.len());
        assert_eq!(ed2.transformers.len(), ed.transformers.len());
        assert_eq!(ed2.generators[&0x0010].name, "Status Broadcast");
        assert_eq!(ed2.interfaces[&0].description, "Primary CAN bus");
    }

    #[test]
    fn from_board_def_converts_correctly() {
        let bd = crate::load_board_def("wiredflexlink", "esp32c6-v0.0.2").unwrap();
        let ed = EditableBoardDef::from_board_def(&bd);

        assert_eq!(ed.name, "wiredflexlink");
        assert_eq!(ed.revision, "esp32c6-v0.0.2");
        assert_eq!(ed.interfaces.len(), bd.interfaces.len());
        assert_eq!(ed.signals.len(), bd.signals.len());
        assert!(!ed.dirty);

        let keys: Vec<SignalKey> = ed.signals.keys().copied().collect();
        let mut sorted = keys.clone();
        sorted.sort();
        assert_eq!(keys, sorted);
    }

    #[test]
    fn to_toml_uses_semantic_signal_keys_and_hex_rule_keys() {
        let ed = EditableBoardDef::from_toml(TEST_TOML).unwrap();
        let output = ed.to_toml();
        assert!(output.contains("[signals.\"interface.0.config.datarate\"]"));
        assert!(output.contains("[frame_defs.0x0001]"));
    }

    #[test]
    fn from_toml_parses_generators_and_transformers() {
        let ed = EditableBoardDef::from_toml(TEST_TOML).unwrap();
        assert_eq!(ed.generators.len(), 1);
        let gdef = &ed.generators[&0x0010];
        assert_eq!(gdef.name, "Status Broadcast");
        assert_eq!(gdef.description, "Broadcasts engine status every 100ms");

        assert_eq!(ed.transformers.len(), 1);
        let xf = &ed.transformers[&0x0020];
        assert_eq!(xf.name, "CAN to LEDs");
        assert_eq!(xf.description, "Maps CAN signals to LED indicators");
    }

    const PASSTHROUGH_TOML: &str = r#"
[board]
name = "testboard"
revision = "v1.0"
description = "Test"

[palettes.0]
name = "Temperature"
description = "Blue to Red"
signal_start = "0x0200"
entries = ["FF0000FF", "FFFF0000"]

[functions.0x10]
name = "Palette Lookup"
description = "Look up colour from palette"
params = ["palette_signal_start:u16", "signal_max:u16"]
"#;

    #[test]
    fn passthrough_preserves_palettes_and_functions() {
        let ed = EditableBoardDef::from_toml(PASSTHROUGH_TOML).unwrap();
        let output = ed.to_toml();

        assert!(output.contains("[palettes.0]"));
        assert!(output.contains("\"Temperature\""));
        assert!(output.contains("[functions.0x10]"));
        assert!(output.contains("\"Palette Lookup\""));
        assert!(output.contains("palette_signal_start:u16"));
    }

    #[test]
    fn from_toml_parses_description_on_entities() {
        let ed = EditableBoardDef::from_toml(TEST_TOML).unwrap();
        assert_eq!(ed.interfaces[&0].description, "Primary CAN bus");
        assert_eq!(ed.interfaces[&1].description, "");
    }

    #[test]
    fn set_pending_and_resolve() {
        let mut ed = EditableBoardDef::from_toml(TEST_TOML).unwrap();
        ed.set_pending_frame_def(0x0001, Some("My Frame".into()), Some("A test frame".into()));
        assert_eq!(ed.resolve_frame_def_name(0x0001), "My Frame");
        assert_eq!(
            ed.resolve_frame_def_description(0x0001),
            Some("A test frame".to_string())
        );
        assert_eq!(ed.resolve_frame_def_name(0x9999), "Frame 0x9999");
        assert_eq!(ed.resolve_frame_def_description(0x9999), None);
        ed.remove_pending_frame_def(0x0001);
        assert_eq!(ed.resolve_frame_def_name(0x0001), "Engine Status");
    }

    #[test]
    fn set_pending_generator_and_transformer() {
        let mut ed = EditableBoardDef::from_toml(TEST_TOML).unwrap();
        ed.set_pending_generator(0x0001, Some("My Gen".into()), None);
        assert_eq!(ed.resolve_generator_name(0x0001), "My Gen");
        assert_eq!(ed.resolve_generator_description(0x0001), None);
        ed.set_pending_transformer(0x0002, None, Some("Desc only".into()));
        assert_eq!(ed.resolve_transformer_name(0x0002), "Transformer 0x0002");
        assert_eq!(
            ed.resolve_transformer_description(0x0002),
            Some("Desc only".to_string())
        );
    }

    #[test]
    fn merge_pending_moves_active_discards_orphans() {
        let mut ed = EditableBoardDef::from_toml(TEST_TOML).unwrap();
        ed.set_pending_frame_def(0x0001, Some("Active".into()), None);
        ed.set_pending_frame_def(0x9999, Some("Orphan".into()), None);
        ed.set_pending_generator(0x0010, Some("Active Gen".into()), None);
        let active = ActiveRuleIds {
            frame_defs: [0x0001].into_iter().collect(),
            generators: [0x0010].into_iter().collect(),
            transformers: HashSet::new(),
        };
        ed.merge_pending(&active);
        assert_eq!(ed.frame_defs[&0x0001].name, "Active");
        assert_eq!(ed.generators[&0x0010].name, "Active Gen");
        assert!(ed.pending.frame_defs.is_empty());
        assert!(ed.pending.generators.is_empty());
    }

    #[test]
    fn pending_does_not_affect_dirty() {
        let mut ed = EditableBoardDef::from_toml(TEST_TOML).unwrap();
        assert!(!ed.dirty);
        ed.set_pending_frame_def(0x0001, Some("Name".into()), None);
        assert!(!ed.dirty);
    }

    #[test]
    fn set_pending_merges_not_replaces() {
        let mut ed = EditableBoardDef::from_toml(TEST_TOML).unwrap();
        ed.set_pending_frame_def(0x0001, Some("My Frame".into()), None);
        ed.set_pending_frame_def(0x0001, None, Some("A description".into()));
        assert_eq!(ed.resolve_frame_def_name(0x0001), "My Frame");
        assert_eq!(
            ed.resolve_frame_def_description(0x0001),
            Some("A description".to_string())
        );
    }

    #[test]
    fn resolve_falls_through_pending_none_to_committed() {
        let mut ed = EditableBoardDef::from_toml(TEST_TOML).unwrap();
        ed.set_pending_frame_def(0x0001, None, Some("Just a desc".into()));
        assert_eq!(ed.resolve_frame_def_name(0x0001), "Engine Status");
        assert_eq!(
            ed.resolve_frame_def_description(0x0001),
            Some("Just a desc".to_string())
        );
    }

    #[test]
    fn merge_pending_onto_existing_committed_preserves_other_fields() {
        let mut ed = EditableBoardDef::from_toml(TEST_TOML).unwrap();
        ed.set_pending_frame_def(0x0001, Some("Renamed".into()), None);
        let active = ActiveRuleIds {
            frame_defs: [0x0001].into_iter().collect(),
            generators: HashSet::new(),
            transformers: HashSet::new(),
        };
        ed.merge_pending(&active);
        let fd = &ed.frame_defs[&0x0001];
        assert_eq!(fd.name, "Renamed");
        assert_eq!(fd.interface_type, "can");
        assert!(fd.can.is_some());
    }

    #[test]
    fn save_and_load_pending_round_trip() {
        let dir = std::env::temp_dir().join("framelink_test_pending");
        let _ = std::fs::create_dir_all(&dir);

        let mut ed = EditableBoardDef::from_toml(TEST_TOML).unwrap();
        ed.set_pending_frame_def(0x0001, Some("My Frame".into()), Some("Desc".into()));
        ed.set_pending_generator(0x0010, Some("My Gen".into()), None);

        ed.save_pending(&dir, "test-device").unwrap();

        let mut ed2 = EditableBoardDef::from_toml(TEST_TOML).unwrap();
        ed2.load_pending(&dir, "test-device").unwrap();

        assert_eq!(ed2.resolve_frame_def_name(0x0001), "My Frame");
        assert_eq!(
            ed2.resolve_frame_def_description(0x0001),
            Some("Desc".to_string())
        );
        assert_eq!(ed2.resolve_generator_name(0x0010), "My Gen");

        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn load_pending_missing_file_is_ok() {
        let dir = std::env::temp_dir().join("framelink_test_no_file");
        let mut ed = EditableBoardDef::from_toml(TEST_TOML).unwrap();
        ed.load_pending(&dir, "nonexistent").unwrap();
        assert!(ed.pending.frame_defs.is_empty());
    }

    #[test]
    fn save_pending_empty_removes_file() {
        let dir = std::env::temp_dir().join("framelink_test_empty");
        let _ = std::fs::create_dir_all(&dir);

        let mut ed = EditableBoardDef::from_toml(TEST_TOML).unwrap();
        ed.set_pending_frame_def(0x0001, Some("Temp".into()), None);
        ed.save_pending(&dir, "test-empty").unwrap();
        assert!(dir.join("test-empty.pending.toml").exists());

        ed.remove_pending_frame_def(0x0001);
        ed.save_pending(&dir, "test-empty").unwrap();
        assert!(!dir.join("test-empty.pending.toml").exists());

        let _ = std::fs::remove_dir_all(&dir);
    }
}
