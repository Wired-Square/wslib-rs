//! Finds the Cortex-A53 erratum 843419 sites an aarch64 linker left unpatched.
//!
//! On the Pi 3 and the Zero 2 W, a load or store based on an `ADRP` at page offset
//! `0xff8` or `0xffc` can use a wrong address when particular instructions sit
//! between them; the fix is the linker's, and only when it is asked for. Each site
//! is found by LLD's own definition, `is843419ErratumSequence` in
//! `lld/ELF/AArch64ErrataFix.cpp`, and a site LLD patched no longer matches it.
//!
//! Only the section headers are read, so each executable section is scanned whole:
//! data in a code section, which LLD skips by its `$d` mapping symbols, can be
//! reported as a site, and no real site is hidden.

use std::path::Path;

const EM_AARCH64: u16 = 183;
const SHT_NOBITS: u32 = 8;
const SHF_EXECINSTR: u64 = 0x4;
const SECTION_HEADER: usize = 64;
const TRUNCATED: &str = "the ELF headers run past the end of the file";

/// The address of every unpatched site's `ADRP` in the aarch64 ELF at `path`.
pub fn unpatched_sites(path: &Path) -> Result<Vec<u64>, String> {
    std::fs::read(path)
        .map_err(|e| e.to_string())
        .and_then(|elf| scan_elf(&elf))
        .map_err(|e| format!("{}: {e}", path.display()))
}

fn scan_elf(elf: &[u8]) -> Result<Vec<u64>, String> {
    if elf.get(..6) != Some(b"\x7fELF\x02\x01".as_slice()) {
        return Err("not a 64-bit little-endian ELF file".into());
    }
    let machine = u16_at(elf, 18)?;
    if machine != EM_AARCH64 {
        return Err(format!(
            "e_machine is {machine}, not aarch64's {EM_AARCH64}"
        ));
    }

    let table = to_usize(u64_at(elf, 0x28)?)?;
    let entry = usize::from(u16_at(elf, 0x3a)?);
    if entry < SECTION_HEADER {
        return Err(format!(
            "e_shentsize is {entry}, under a section header's {SECTION_HEADER}"
        ));
    }
    let count = usize::from(u16_at(elf, 0x3c)?);
    let mut sites = Vec::new();
    let mut scanned = 0usize;
    for i in 0..count {
        let header = i
            .checked_mul(entry)
            .and_then(|offset| offset.checked_add(table))
            .and_then(|at| elf.get(at..at.checked_add(SECTION_HEADER)?))
            .ok_or(TRUNCATED)?;
        if u32_at(header, 4)? == SHT_NOBITS || u64_at(header, 8)? & SHF_EXECINSTR == 0 {
            continue;
        }
        let address = u64_at(header, 16)?;
        let start = to_usize(u64_at(header, 24)?)?;
        let code = start
            .checked_add(to_usize(u64_at(header, 32)?)?)
            .and_then(|end| elf.get(start..end))
            .ok_or("a section runs past the end of the file")?;
        sites.extend(scan(address, code));
        scanned += 1;
    }
    if scanned == 0 {
        return Err("no executable section to scan".into());
    }
    Ok(sites)
}

fn scan(address: u64, code: &[u8]) -> Vec<u64> {
    let words: Vec<u32> = code
        .as_chunks::<4>()
        .0
        .iter()
        .map(|w| u32::from_le_bytes(*w))
        .collect();
    (0..words.len())
        .map(|i| (address.wrapping_add(4 * i as u64), &words[i..]))
        .filter(|&(at, window)| matches!(at & 0xfff, 0xff8 | 0xffc) && triggers(window))
        .map(|(at, _)| at)
        .collect()
}

/// LLD's scan: the sequence in three instructions, or in four when the third is
/// not a branch — which is all it asks of the third.
fn triggers(window: &[u32]) -> bool {
    match *window {
        [adrp, second, third, ref rest @ ..] => {
            is_843419_sequence(adrp, second, third)
                || (!is_branch(third)
                    && rest
                        .first()
                        .is_some_and(|&fourth| is_843419_sequence(adrp, second, fourth)))
        }
        _ => false,
    }
}

fn is_843419_sequence(adrp: u32, second: u32, last: u32) -> bool {
    if !is_adrp(adrp) {
        return false;
    }
    let rn = rt(adrp);
    is_load_store_class(second)
        && (is_load_store_exclusive(second)
            || is_load_literal(second)
            || is_single_register_load_store(second)
            || is_stp(second)
            || is_stnp(second)
            || is_st1(second))
        && !writes_register(second, rn)
        && is_load_store_unsigned(last)
        && base(last) == rn
}

fn is_adrp(i: u32) -> bool {
    i & 0x9f00_0000 == 0x9000_0000
}

fn is_load_store_class(i: u32) -> bool {
    i & 0x0a00_0000 == 0x0800_0000
}

fn is_st1_multiple_opcode(i: u32) -> bool {
    matches!(i & 0x0000_f000, 0x2000 | 0x6000 | 0x7000 | 0xa000)
}

fn is_st1_multiple(i: u32) -> bool {
    i & 0xbfff_0000 == 0x0c00_0000 && is_st1_multiple_opcode(i)
}

fn is_st1_multiple_post(i: u32) -> bool {
    i & 0xbfe0_0000 == 0x0c80_0000 && is_st1_multiple_opcode(i)
}

fn is_st1_single_opcode(i: u32) -> bool {
    matches!(i & 0x0040_e000, 0x0000 | 0x4000 | 0x8000)
}

fn is_st1_single(i: u32) -> bool {
    i & 0xbfff_0000 == 0x0d00_0000 && is_st1_single_opcode(i)
}

fn is_st1_single_post(i: u32) -> bool {
    i & 0xbfe0_0000 == 0x0d80_0000 && is_st1_single_opcode(i)
}

fn is_st1(i: u32) -> bool {
    is_st1_multiple(i) || is_st1_multiple_post(i) || is_st1_single(i) || is_st1_single_post(i)
}

fn is_load_store_exclusive(i: u32) -> bool {
    i & 0x3f00_0000 == 0x0800_0000
}

fn is_load_exclusive(i: u32) -> bool {
    i & 0x3f40_0000 == 0x0840_0000
}

fn is_load_literal(i: u32) -> bool {
    i & 0x3b00_0000 == 0x1800_0000
}

fn is_stnp(i: u32) -> bool {
    i & 0x3bc0_0000 == 0x2800_0000
}

fn is_stp_post(i: u32) -> bool {
    i & 0x3bc0_0000 == 0x2880_0000
}

fn is_stp_pre(i: u32) -> bool {
    i & 0x3bc0_0000 == 0x2980_0000
}

fn is_stp(i: u32) -> bool {
    is_stp_post(i) || i & 0x3bc0_0000 == 0x2900_0000 || is_stp_pre(i)
}

fn is_load_store_immediate_post(i: u32) -> bool {
    i & 0x3b20_0c00 == 0x3800_0400
}

fn is_load_store_immediate_pre(i: u32) -> bool {
    i & 0x3b20_0c00 == 0x3800_0c00
}

fn is_load_store_unsigned(i: u32) -> bool {
    i & 0x3b00_0000 == 0x3900_0000
}

fn is_single_register_load_store(i: u32) -> bool {
    i & 0x3b00_0c00 == 0x3800_0000
        || is_load_store_immediate_post(i)
        || i & 0x3b20_0c00 == 0x3800_0800
        || is_load_store_immediate_pre(i)
        || i & 0x3b20_0c00 == 0x3820_0800
        || is_load_store_unsigned(i)
}

/// An ARMv8.0 load: exclusive, literal, or a single-register form whose `opc` is
/// not 0 — and not 2 where that is a store (`size 0, V 1`) or a prefetch (`size 3, V 0`).
fn is_load(i: u32) -> bool {
    if is_load_exclusive(i) || is_load_literal(i) {
        return true;
    }
    let (size, v, opc) = (i >> 30, (i >> 26) & 1, (i >> 22) & 3);
    is_single_register_load_store(i)
        && opc != 0
        && !(size == 0 && v == 1 && opc == 2)
        && !(size == 3 && v == 0 && opc == 2)
}

fn has_writeback(i: u32) -> bool {
    is_load_store_immediate_pre(i)
        || is_load_store_immediate_post(i)
        || is_stp_pre(i)
        || is_stp_post(i)
        || is_st1_single_post(i)
        || is_st1_multiple_post(i)
}

fn writes_register(i: u32, register: u32) -> bool {
    (is_load(i) && rt(i) == register) || (has_writeback(i) && base(i) == register)
}

fn is_branch(i: u32) -> bool {
    i & 0xfe00_0000 == 0xd600_0000
        || i & 0xfe00_0000 == 0x5400_0000
        || i & 0x7c00_0000 == 0x1400_0000
        || i & 0x7c00_0000 == 0x3400_0000
}

fn rt(i: u32) -> u32 {
    i & 0x1f
}

fn base(i: u32) -> u32 {
    (i >> 5) & 0x1f
}

fn bytes<const N: usize>(elf: &[u8], at: usize) -> Result<[u8; N], String> {
    at.checked_add(N)
        .and_then(|end| elf.get(at..end))
        .and_then(|b| b.try_into().ok())
        .ok_or_else(|| TRUNCATED.into())
}

fn u16_at(elf: &[u8], at: usize) -> Result<u16, String> {
    bytes(elf, at).map(u16::from_le_bytes)
}

fn u32_at(elf: &[u8], at: usize) -> Result<u32, String> {
    bytes(elf, at).map(u32::from_le_bytes)
}

fn u64_at(elf: &[u8], at: usize) -> Result<u64, String> {
    bytes(elf, at).map(u64::from_le_bytes)
}

fn to_usize(n: u64) -> Result<usize, String> {
    usize::try_from(n).map_err(|_| format!("{n} does not fit this host's address space"))
}

#[cfg(test)]
mod tests {
    use super::*;

    const ADRP_X1: u32 = 0x9000_0001;
    const LDR_X2_FROM_X3: u32 = 0xf940_0062;
    const LDR_X5_FROM_X1: u32 = 0xf940_0025;
    const STR_X2_TO_X3: u32 = 0xf900_0062;
    const NOP: u32 = 0xd503_201f;
    const MOV_X1_X9: u32 = 0xaa09_03e1;
    const B_NEXT: u32 = 0x1400_0001;
    const SITE: &[u32] = &[ADRP_X1, LDR_X2_FROM_X3, LDR_X5_FROM_X1];

    /// The sites in `words`, laid out so the first sits at page offset `first`.
    fn sites_from(first: u64, words: &[u32]) -> Vec<u64> {
        let code: Vec<u8> = words.iter().flat_map(|w| w.to_le_bytes()).collect();
        scan(0x40_0000 + first, &code)
    }

    fn found(first: u64, words: &[u32]) -> bool {
        sites_from(first, words) == [0x40_0000 + first]
    }

    #[test]
    fn three_instructions_trigger_at_either_page_offset() {
        for offset in [0xff8, 0xffc] {
            assert!(found(offset, SITE));
        }
    }

    #[test]
    fn four_instructions_trigger_with_a_non_branch_between() {
        assert!(found(0xff8, &[ADRP_X1, STR_X2_TO_X3, NOP, LDR_X5_FROM_X1]));
    }

    #[test]
    fn the_third_is_not_checked_for_writing_the_register_as_lld_does_not() {
        assert!(found(
            0xffc,
            &[ADRP_X1, LDR_X2_FROM_X3, MOV_X1_X9, LDR_X5_FROM_X1]
        ));
    }

    #[test]
    fn only_an_adrp_opens_a_sequence() {
        for (first, mnemonic, reported) in [
            (0xb000_0001, "adrp x1, 0x1000", true),
            (0x1000_0001, "adr x1, .", false),
        ] {
            let site = [first, LDR_X2_FROM_X3, LDR_X5_FROM_X1];
            assert_eq!(found(0xff8, &site), reported, "{mnemonic}");
        }
    }

    /// One encoding per rule for the second instruction, each assembled with
    /// `zig cc -c` and read back with objdump. A register-1 store is still a
    /// site; anything that loads into or writes back to x1 is not.
    #[test]
    fn each_rule_for_the_second_instruction() {
        for (second, mnemonic, reported) in [
            (0xf900_0061, "str x1, [x3]", true),
            (0x3d80_0061, "str q1, [x3]", true),
            (0xf980_0061, "prfm pldl1strm, [x3]", true),
            (0xc804_7c61, "stxr w4, x1, [x3]", true),
            (0x5800_0022, "ldr x2, <literal>", true),
            (0xa800_1061, "stnp x1, x4, [x3]", true),
            (0xf81f_8061, "stur x1, [x3, #-8]", true),
            (0xf800_0861, "sttr x1, [x3]", true),
            (0xf824_6861, "str x1, [x3, x4]", true),
            (0xf81f_8c61, "str x1, [x3, #-8]!", true),
            (0xf800_8461, "str x1, [x3], #8", true),
            (0xa900_1061, "stp x1, x4, [x3]", true),
            (0xa881_1061, "stp x1, x4, [x3], #16", true),
            (0xa9bf_1061, "stp x1, x4, [x3, #-16]!", true),
            (0x4c00_2061, "st1 {v1.16b-v4.16b}, [x3]", true),
            (0x4c00_6061, "st1 {v1.16b-v3.16b}, [x3]", true),
            (0x4c00_7061, "st1 {v1.16b}, [x3]", true),
            (0x4c00_a061, "st1 {v1.16b, v2.16b}, [x3]", true),
            (0x4c9f_7061, "st1 {v1.16b}, [x3], #16", true),
            (0x0d00_0061, "st1 {v1.b}[0], [x3]", true),
            (0x0d00_4061, "st1 {v1.h}[0], [x3]", true),
            (0x0d00_8061, "st1 {v1.s}[0], [x3]", true),
            (0x0d00_8461, "st1 {v1.d}[0], [x3]", true),
            (0x0d9f_0061, "st1 {v1.b}[0], [x3], #1", true),
            (0xf940_0061, "ldr x1, [x3]", false),
            (0x5800_0021, "ldr x1, <literal>", false),
            (0xc85f_7c61, "ldxr x1, [x3]", false),
            (0xf840_8422, "ldr x2, [x1], #8", false),
            (0xf81f_8c22, "str x2, [x1, #-8]!", false),
            (0xf800_8422, "str x2, [x1], #8", false),
            (0xa9bf_0c22, "stp x2, x3, [x1, #-16]!", false),
            (0xa881_0c22, "stp x2, x3, [x1], #16", false),
            (0x4c9f_7020, "st1 {v0.16b}, [x1], #16", false),
            (0x0d9f_0020, "st1 {v0.b}[0], [x1], #1", false),
            (NOP, "nop", false),
        ] {
            let site = [ADRP_X1, second, LDR_X5_FROM_X1];
            assert_eq!(found(0xff8, &site), reported, "{mnemonic}");
        }
    }

    #[test]
    fn no_branch_may_sit_third() {
        for (third, mnemonic) in [
            (B_NEXT, "b"),
            (0x5400_0020, "b.eq"),
            (0xd61f_0120, "br x9"),
            (0xb400_0029, "cbz x9"),
            (0x3600_0029, "tbz w9, #0"),
        ] {
            let site = [ADRP_X1, LDR_X2_FROM_X3, third, LDR_X5_FROM_X1];
            assert!(sites_from(0xff8, &site).is_empty(), "{mnemonic}");
        }
    }

    #[test]
    fn any_other_page_offset_is_not_a_site() {
        for offset in [0x000, 0x004, 0xff0, 0xff4] {
            assert!(sites_from(offset, SITE).is_empty());
        }
    }

    #[test]
    fn the_last_access_must_use_the_adrp_register() {
        assert!(sites_from(0xff8, &[ADRP_X1, LDR_X2_FROM_X3, LDR_X2_FROM_X3]).is_empty());
    }

    #[test]
    fn a_last_access_outside_the_unsigned_immediate_class_is_not_a_site() {
        let ldur_x5_from_x1 = 0xf840_0025;
        assert!(sites_from(0xff8, &[ADRP_X1, LDR_X2_FROM_X3, ldur_x5_from_x1]).is_empty());
    }

    #[test]
    fn a_patched_site_no_longer_matches() {
        assert!(sites_from(0xff8, &[ADRP_X1, LDR_X2_FROM_X3, B_NEXT]).is_empty());
    }

    #[test]
    fn a_sequence_cut_off_by_the_section_end_is_not_a_site() {
        assert!(sites_from(0xff8, &[ADRP_X1, LDR_X2_FROM_X3]).is_empty());
    }

    const PROGBITS: u32 = 1;
    const EXEC: u64 = SHF_EXECINSTR;

    /// An ELF with one section per `(type, flags, words)`, each starting at page
    /// offset `0xff8` of its own page.
    fn elf(machine: u16, sections: &[(u32, u64, &[u32])]) -> Vec<u8> {
        let mut out = vec![0u8; 64];
        out[..6].copy_from_slice(b"\x7fELF\x02\x01");
        out[18..20].copy_from_slice(&machine.to_le_bytes());
        let mut headers = Vec::new();
        for (page, (kind, flags, words)) in (1u64..).zip(sections) {
            let offset = out.len() as u64;
            out.extend(words.iter().flat_map(|w| w.to_le_bytes()));
            let mut header = [0u8; 64];
            header[4..8].copy_from_slice(&kind.to_le_bytes());
            header[8..16].copy_from_slice(&flags.to_le_bytes());
            header[16..24].copy_from_slice(&(page * 0x1000 + 0xff8).to_le_bytes());
            header[24..32].copy_from_slice(&offset.to_le_bytes());
            header[32..40].copy_from_slice(&(words.len() as u64 * 4).to_le_bytes());
            headers.extend(header);
        }
        let table = out.len() as u64;
        out.extend(headers);
        out[0x28..0x30].copy_from_slice(&table.to_le_bytes());
        out[0x3a..0x3c].copy_from_slice(&64u16.to_le_bytes());
        out[0x3c..0x3e].copy_from_slice(&(sections.len() as u16).to_le_bytes());
        out
    }

    #[test]
    fn only_executable_sections_with_contents_are_scanned() {
        let binary = elf(
            EM_AARCH64,
            &[
                (PROGBITS, EXEC, SITE),
                (PROGBITS, 0x2, SITE),
                (SHT_NOBITS, EXEC, SITE),
            ],
        );
        assert_eq!(scan_elf(&binary), Ok(vec![0x1ff8]));
    }

    #[test]
    fn a_binary_for_another_machine_is_refused() {
        assert!(scan_elf(&elf(62, &[(PROGBITS, EXEC, &[NOP])])).is_err());
    }

    #[test]
    fn a_binary_with_nothing_executable_is_refused() {
        assert!(scan_elf(&elf(EM_AARCH64, &[(PROGBITS, 0x2, &[NOP])])).is_err());
    }

    #[test]
    fn a_malformed_section_table_is_refused_rather_than_overflowing() {
        let mut far = elf(EM_AARCH64, &[(PROGBITS, EXEC, SITE)]);
        far[0x28..0x30].copy_from_slice(&(u64::MAX - 8).to_le_bytes());
        assert!(scan_elf(&far).is_err());

        let mut short = elf(EM_AARCH64, &[(PROGBITS, EXEC, SITE)]);
        short[0x3a..0x3c].copy_from_slice(&32u16.to_le_bytes());
        assert!(scan_elf(&short).is_err());
    }
}
