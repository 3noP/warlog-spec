# Registry Preview

This directory is a static preview of the future Warlog Spec registry.
It is not a hosted discovery service and it does not perform install,
signature, or validation workflows.

`index.json` exists so adopters can see the intended registry shape:
packages, connector examples, declared conformance levels, validation
status, and compatibility range. Entries should stay conservative. Do
not mark a connector as live-validated unless a maintainer can point to
the tenant or lab validation evidence.

Future registry work may add:

- signed publisher metadata
- pack and connector signatures
- hosted API/search
- air-gapped import bundles
- validation evidence attachments