# {{name}}'s image, built by scaffold/packaging/make-image.sh from the context it
# stages. Owned by wslib-appliance-xtask, and rewritten unconditionally by every
# render.
#
# The app serves app.sock and hooks.sock in the directory the console mounts at
# /run/appliance.
# The console's stop timeout must exceed the daemon's 22 s grace, past Docker's
# default of 10 s, or the drain is killed.
# The console runs it as a uid of its choosing in group 0, which owns everything
# the app writes and is how a root console with no capabilities reaches the
# sockets. No HEALTHCHECK: the console probes healthz over app.sock.
#
{{capabilities_stage}}# distroless for the CA bundle the app's outbound trust reads.
FROM gcr.io/distroless/static-debian13@sha256:58133991db06659feaabe0f4e97a35cebf15ef4ea08f8a4c6d2ee5f75e4aa6a0

{{binary_copy}}
{{ui_copy}}

# Each volume and the socket directory is copied into its parent, never onto
# itself: an older BuildKit does not chmod a copy's destination. An empty copy
# first makes a missing parent root's.
{{volumes}}
COPY --chown=10001:0 --chmod=0770 sock/ /run/

# SQLite's temporary files go in the data volume.
ENV CONFIGURATION_DIRECTORY={{config_dir}} \
    STATE_DIRECTORY={{state_dir}} \
    TMPDIR={{state_dir}} \
    {{env_prefix}}_APP_SOCKET=/run/appliance/app.sock \
    {{env_prefix}}_HOOKS_SOCKET=/run/appliance/hooks.sock \
    {{env_prefix}}_CONSOLE_UID=0 \
    {{env_prefix}}_BASE_PATH=/apps/{{name}}/

VOLUME {{volume_paths}}
LABEL {{labels}}
USER 10001:0
WORKDIR /
ENTRYPOINT ["/usr/bin/{{binary}}"]
