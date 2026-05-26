"""AWS multi-service response connector — reference implementation.

Wraps boto3 against AWS IAM, KMS, S3, EC2 to implement the canonical
SOC cloud-IR sub-graph against an AWS account.

Actions covered (cloud audit, see ``docs/canon-migration/15-cloud-gap-audit.md``
and the doctrine refinement in ``docs/canon-migration/16-doctrine-refinement.md``):

- :data:`ResponseActionId.HOST_STOP`               → EC2 StopInstances
- :data:`ResponseActionId.HOST_START`              → EC2 StartInstances (inverse)
- :data:`ResponseActionId.HOST_DELETE`             → EC2 TerminateInstances
- :data:`ResponseActionId.IAM_ROLE_DETACH`         → DetachUserPolicy / DetachRolePolicy
- :data:`ResponseActionId.IAM_ROLE_ATTACH`         → AttachUserPolicy / AttachRolePolicy (inverse)
- :data:`ResponseActionId.IAM_CREDENTIALS_DISABLE` → UpdateAccessKey Status=Inactive
- :data:`ResponseActionId.IAM_CREDENTIALS_ENABLE`  → UpdateAccessKey Status=Active (inverse)
- :data:`ResponseActionId.IAM_CREDENTIALS_ROTATE`  → CreateAccessKey + DeleteAccessKey old
- :data:`ResponseActionId.KEY_DISABLE`             → KMS DisableKey
- :data:`ResponseActionId.KEY_ENABLE`              → KMS EnableKey (inverse)
- :data:`ResponseActionId.KEY_ROTATE`              → KMS RotateKeyOnDemand (forces a new version *now*, not the annual auto-rotation toggle)
- :data:`ResponseActionId.KEY_SCHEDULE_DELETION`   → KMS ScheduleKeyDeletion (7-30 day window)
- :data:`ResponseActionId.BUCKET_LOCKDOWN`         → S3 PutPublicAccessBlock + restrictive bucket policy
- :data:`ResponseActionId.BUCKET_UNLOCK`           → S3 DeletePublicAccessBlock + DeleteBucketPolicy (removes lockdown artifacts ; does NOT restore arbitrary prior policy)

**Auth model :** standard boto3 credential chain (instance profile,
environment variables, AWS_PROFILE, SSO). The reference does NOT
implement explicit credential plumbing — production deployments
inject credentials via the AWS-recommended chain. AWS uses long-
lived AccessKey/SecretKey pairs at the wire level (signed via
SigV4) ; from the canonical-auth-model perspective this is
``API_KEY`` semantics, not OAuth2.

Cross-account access uses STS AssumeRole, which is configured via
``config['assume_role_arn']`` at construction. The actual STS call
is deferred to :meth:`authenticate` so credential errors flow
through the runner's standard error mapping (instead of leaking out
of ``__init__`` as raw boto3 exceptions).

**Why boto3 instead of raw HTTP :** AWS Signature V4 is a complex
canonical-request signing flow that nobody hand-rolls in production.
boto3 (or the AWS SDK in the language of choice) is the realistic
reference for any AWS connector. Honest scoping : we don't pretend
HTTP-level wrapping is the integration point for AWS.

Configuration shape::

    {
        "region": "us-east-1",
        "assume_role_arn": "arn:aws:iam::123:role/WarlogResponse",  # optional
        "delete_old_after_rotation": true,  # default True ; set False to keep old creds around for safety
    }

**Important — credentials_rotate secret handling :** AWS only returns
the new ``SecretAccessKey`` once, at ``CreateAccessKey`` time. If
the orchestrator does not capture it during the same call, it is
lost forever and the rotated principal becomes unable to authenticate.
This connector surfaces the new secret material in
``ResponseActionResult.details['vendor_secret_material']`` so the
runtime's outbox / Vault writer can persist it before the action is
considered terminal. Setting ``config['delete_old_after_rotation']
= False`` is the safety mode : the old key stays Active so a
distribution failure does not lock the principal out.

What this file proves :

- The same ABI shape that drove the Okta / Falcon / PAN-OS examples
  fits a vendor with FOUR distinct service surfaces (IAM, KMS, S3,
  EC2) by routing per action_id rather than per service.
- The DESTRUCTIVE / DISRUPTIVE classification carved out in audit 14
  shows up operationally : ``key.schedule_deletion`` is gated through
  MANAGER + 2 reviewers because the canonical action catalog says so,
  not because the connector imposes its own policy.
- ``params_schema_ref`` validation (runner-enforced) catches
  ``cooldown_days`` violations before the AWS API is ever called.
- Block / unblock pairs are symmetric : every disruptive action ships
  its inverse so an analyst's audit chain shows both steps as
  canonical events.

**Runtime-test status :** spec-conformant, written against AWS API
contracts via boto3. Not yet exercised against a live AWS account in
this repo's CI. PRs welcome from anyone running it against their dev
account.

Requires ``boto3`` (real AWS dependency, install separately).
"""

from __future__ import annotations

import asyncio
import json
from typing import Any, ClassVar
from uuid import uuid4

from warlog_spec import (
    AbiConnector,
    AuthDescriptor,
    ConnectorAbiError,
    ConnectorAuthModel,
    ConnectorCapability,
    ConnectorCompat,
    ConnectorKind,
    DryRunDescriptor,
    DryRunScope,
    EgressDescriptor,
    ExecutionOutcome,
    FailureCategory,
    LifecycleDescriptor,
    ResponseActionId,
    ResponseActionResult,
    ResponseActionSpec,
)


class AwsResponseConnector(AbiConnector):
    """ABI connector for AWS multi-service IR response."""

    capability: ClassVar[ConnectorCapability] = ConnectorCapability(
        connector_id="aws-multi-service",
        connector_version="0.2.0",
        vendor="Amazon Web Services",
        kind=ConnectorKind.OTHER,  # spans IAM + storage + compute
        # AWS uses long-lived AccessKey/SecretKey pairs (signed via
        # SigV4 at the wire level). From the canonical-auth-model
        # perspective this is API_KEY, not OAuth2 — OAuth2 is the
        # IdC / Identity Center flow which is a separate path not
        # exercised by this reference.
        auth=AuthDescriptor(
            model=ConnectorAuthModel.API_KEY,
            scopes=[
                "iam:UpdateAccessKey",
                "iam:DetachRolePolicy",
                "iam:DetachUserPolicy",
                "iam:AttachRolePolicy",
                "iam:AttachUserPolicy",
                "iam:CreateAccessKey",
                "iam:DeleteAccessKey",
                "kms:DisableKey",
                "kms:EnableKey",
                "kms:RotateKeyOnDemand",
                "kms:ScheduleKeyDeletion",
                "s3:PutPublicAccessBlock",
                "s3:DeletePublicAccessBlock",
                "s3:PutBucketPolicy",
                "s3:DeleteBucketPolicy",
                "ec2:StopInstances",
                "ec2:StartInstances",
                "ec2:TerminateInstances",
                "sts:AssumeRole",
            ],
        ),
        egress=EgressDescriptor(
            supports_response_actions=[
                ResponseActionId.HOST_STOP,
                ResponseActionId.HOST_START,
                ResponseActionId.HOST_DELETE,
                ResponseActionId.IAM_ROLE_DETACH,
                ResponseActionId.IAM_ROLE_ATTACH,
                ResponseActionId.IAM_CREDENTIALS_DISABLE,
                ResponseActionId.IAM_CREDENTIALS_ENABLE,
                ResponseActionId.IAM_CREDENTIALS_ROTATE,
                ResponseActionId.KEY_DISABLE,
                ResponseActionId.KEY_ENABLE,
                ResponseActionId.KEY_ROTATE,
                ResponseActionId.KEY_SCHEDULE_DELETION,
                ResponseActionId.BUCKET_LOCKDOWN,
                ResponseActionId.BUCKET_UNLOCK,
            ]
        ),
        dry_run=DryRunDescriptor(supported=True, scope=DryRunScope.EGRESS),
        lifecycle=LifecycleDescriptor(
            supports_health_check=True,
            supports_credential_rotation=True,
        ),
        compat=ConnectorCompat(warlog_spec_min="1.0.0", warlog_spec_max="1.x"),
    )

    def __init__(self, config: dict[str, object]) -> None:
        super().__init__(config)
        region = config.get("region")
        if not isinstance(region, str) or not region:
            raise ConnectorAbiError(
                FailureCategory.POLICY,
                "aws: config['region'] is required",
            )
        self._region = region
        self._assume_role_arn = config.get("assume_role_arn")
        self._delete_old_after_rotation = bool(
            config.get("delete_old_after_rotation", True)
        )
        # Lazy-import boto3 — keeps the package's hard deps minimal.
        # Production AWS connectors require boto3 ; the import error
        # surfaces a clear remediation pointer.
        try:
            import boto3  # noqa: F401
        except ImportError as exc:
            raise ConnectorAbiError(
                FailureCategory.POLICY,
                "aws: boto3 is required (`pip install boto3`)",
            ) from exc
        # Session is constructed lazily in authenticate() so any STS
        # AssumeRole error flows through the runner's standard error
        # mapping rather than escaping __init__ as raw boto3 exception.
        self._session: Any | None = None
        self._applied: dict[str, str] = {}

    # -- Lifecycle hooks --------------------------------------------------

    async def authenticate(self) -> None:
        loop = asyncio.get_running_loop()
        try:
            self._session = await loop.run_in_executor(None, self._build_session)
        except Exception as exc:  # noqa: BLE001
            raise _map_aws_error(exc, op="authenticate")
        # Smoke the credential chain with a no-op GetCallerIdentity call.
        try:
            await loop.run_in_executor(None, self._call_get_caller_identity)
        except Exception as exc:  # noqa: BLE001
            raise _map_aws_error(exc, op="authenticate")

    def _build_session(self) -> Any:
        import boto3

        if isinstance(self._assume_role_arn, str) and self._assume_role_arn:
            sts = boto3.client("sts", region_name=self._region)
            assumed = sts.assume_role(
                RoleArn=self._assume_role_arn,
                RoleSessionName=f"warlog-response-{uuid4().hex[:8]}",
            )
            creds = assumed["Credentials"]
            return boto3.Session(
                aws_access_key_id=creds["AccessKeyId"],
                aws_secret_access_key=creds["SecretAccessKey"],
                aws_session_token=creds["SessionToken"],
                region_name=self._region,
            )
        return boto3.Session(region_name=self._region)

    def _call_get_caller_identity(self) -> None:
        assert self._session is not None
        sts = self._session.client("sts")
        sts.get_caller_identity()

    async def dry_run(self, spec: ResponseActionSpec) -> None:
        if spec.action_id not in _SUPPORTED:
            raise ConnectorAbiError(
                FailureCategory.POLICY,
                f"aws does not implement {spec.action_id.value!r}",
            )
        if not spec.subject.selector_value:
            raise ConnectorAbiError(
                FailureCategory.NOT_FOUND,
                "aws: subject.selector_value is required",
            )
        # Per-action subject-shape checks — the runner has already
        # validated params against the canonical schema, here we just
        # confirm the subject is the right kind.
        if spec.action_id in {
            ResponseActionId.IAM_ROLE_DETACH,
            ResponseActionId.IAM_ROLE_ATTACH,
        } and spec.subject.selector_type not in {"iam_user", "iam_role"}:
            raise ConnectorAbiError(
                FailureCategory.POLICY,
                f"aws {spec.action_id.value} requires "
                "subject.selector_type in {'iam_user', 'iam_role'}",
            )
        if spec.action_id in {
            ResponseActionId.IAM_CREDENTIALS_DISABLE,
            ResponseActionId.IAM_CREDENTIALS_ENABLE,
            ResponseActionId.IAM_CREDENTIALS_ROTATE,
        } and spec.subject.selector_type != "access_key_id":
            raise ConnectorAbiError(
                FailureCategory.POLICY,
                f"aws {spec.action_id.value} requires "
                "subject.selector_type='access_key_id' (selector_value=AccessKeyId)",
            )
        if spec.action_id in {
            ResponseActionId.HOST_STOP,
            ResponseActionId.HOST_START,
            ResponseActionId.HOST_DELETE,
        } and spec.subject.selector_type != "instance_id":
            raise ConnectorAbiError(
                FailureCategory.POLICY,
                f"aws {spec.action_id.value} requires "
                "subject.selector_type='instance_id'",
            )

    async def apply(self, spec: ResponseActionSpec) -> ResponseActionResult:
        cached = self._applied.get(spec.idempotency_key)
        if cached is not None:
            return _cached_success(spec, vendor_resource_id=cached)

        if self._session is None:
            raise ConnectorAbiError(
                FailureCategory.AUTH,
                "aws: authenticate() must run before apply",
            )

        loop = asyncio.get_running_loop()
        try:
            details = await loop.run_in_executor(None, self._dispatch, spec)
        except ConnectorAbiError:
            raise
        except Exception as exc:  # noqa: BLE001
            raise _map_aws_error(exc, op=f"apply:{spec.action_id.value}")

        self._applied[spec.idempotency_key] = details["vendor_resource_id"]
        return ResponseActionResult(
            execution_id="",  # the runtime stamps it
            action_id=spec.action_id,
            outcome=ExecutionOutcome.SUCCESS,
            subject=spec.subject,
            details={**details, "vendor_dedup": False},
        )

    async def verify(
        self, spec: ResponseActionSpec, result: ResponseActionResult
    ) -> bool:
        # AWS APIs are eventually consistent ; verification reads back
        # the relevant resource state. For destructive actions
        # (key.schedule_deletion, host.delete, credentials_rotate),
        # the apply 2xx is the contract — verify returns True.
        if spec.action_id in {
            ResponseActionId.KEY_SCHEDULE_DELETION,
            ResponseActionId.HOST_DELETE,
            ResponseActionId.IAM_CREDENTIALS_ROTATE,
        }:
            return True
        if self._session is None:
            return False
        loop = asyncio.get_running_loop()
        try:
            return await loop.run_in_executor(None, self._verify_state, spec)
        except Exception as exc:  # noqa: BLE001
            raise _map_aws_error(exc, op=f"verify:{spec.action_id.value}")

    # -- Vendor dispatch (all sync, called from executor) ----------------

    def _dispatch(self, spec: ResponseActionSpec) -> dict[str, Any]:
        """Route the action to the right boto3 client and return a
        ``details`` dict for the audit row.

        ``details`` always carries ``vendor_resource_id`` (a stable
        correlator the audit chain logs) and may carry action-specific
        metadata such as ``vendor_secret_material`` for credentials
        rotation.
        """
        if spec.action_id is ResponseActionId.IAM_ROLE_DETACH:
            return self._iam_role_change(spec, attach=False)
        if spec.action_id is ResponseActionId.IAM_ROLE_ATTACH:
            return self._iam_role_change(spec, attach=True)
        if spec.action_id is ResponseActionId.IAM_CREDENTIALS_DISABLE:
            return self._iam_credentials_status(spec, status="Inactive")
        if spec.action_id is ResponseActionId.IAM_CREDENTIALS_ENABLE:
            return self._iam_credentials_status(spec, status="Active")
        if spec.action_id is ResponseActionId.IAM_CREDENTIALS_ROTATE:
            return self._iam_credentials_rotate(spec)
        if spec.action_id is ResponseActionId.KEY_DISABLE:
            return self._kms_set_state(spec, enabled=False)
        if spec.action_id is ResponseActionId.KEY_ENABLE:
            return self._kms_set_state(spec, enabled=True)
        if spec.action_id is ResponseActionId.KEY_ROTATE:
            return self._kms_rotate_now(spec)
        if spec.action_id is ResponseActionId.KEY_SCHEDULE_DELETION:
            return self._kms_schedule_deletion(spec)
        if spec.action_id is ResponseActionId.BUCKET_LOCKDOWN:
            return self._s3_bucket_lockdown(spec)
        if spec.action_id is ResponseActionId.BUCKET_UNLOCK:
            return self._s3_bucket_unlock(spec)
        if spec.action_id is ResponseActionId.HOST_STOP:
            return self._ec2_state(spec, action="stop")
        if spec.action_id is ResponseActionId.HOST_START:
            return self._ec2_state(spec, action="start")
        if spec.action_id is ResponseActionId.HOST_DELETE:
            return self._ec2_state(spec, action="terminate")
        raise ConnectorAbiError(
            FailureCategory.POLICY,
            f"aws: unroutable action {spec.action_id.value!r}",
        )

    def _iam_role_change(
        self, spec: ResponseActionSpec, *, attach: bool
    ) -> dict[str, Any]:
        assert self._session is not None
        iam = self._session.client("iam")
        principal = spec.subject.selector_value
        policy_arn = spec.params["policy_id"]
        if spec.subject.selector_type == "iam_user":
            if attach:
                iam.attach_user_policy(UserName=principal, PolicyArn=policy_arn)
            else:
                iam.detach_user_policy(UserName=principal, PolicyArn=policy_arn)
        else:
            if attach:
                iam.attach_role_policy(RoleName=principal, PolicyArn=policy_arn)
            else:
                iam.detach_role_policy(RoleName=principal, PolicyArn=policy_arn)
        verb = "attached" if attach else "detached"
        return {
            "vendor_resource_id": f"{verb}:{spec.subject.selector_type}:{principal}:{policy_arn}",
        }

    def _iam_credentials_status(
        self, spec: ResponseActionSpec, *, status: str
    ) -> dict[str, Any]:
        assert self._session is not None
        iam = self._session.client("iam")
        access_key_id = spec.subject.selector_value
        # principal_id is canonical (validated by the runner against
        # iam.credentials_disable.json) ; we map it to AWS's UserName
        # at the API boundary.
        owner = spec.params["principal_id"]
        iam.update_access_key(
            UserName=owner, AccessKeyId=access_key_id, Status=status
        )
        return {
            "vendor_resource_id": f"access_key:{status.lower()}:{access_key_id}",
        }

    def _iam_credentials_rotate(self, spec: ResponseActionSpec) -> dict[str, Any]:
        assert self._session is not None
        iam = self._session.client("iam")
        old_key = spec.subject.selector_value
        owner = spec.params["principal_id"]
        # Step 1 : create the new key. The SecretAccessKey is ONLY
        # available in this response — if we lose it here, the
        # rotated principal is locked out forever. Surface it
        # explicitly in details so the runtime can pipe it through
        # a Vault writer (or the orchestrator's secret-distribution
        # outbox) before the action is finalized.
        new_key = iam.create_access_key(UserName=owner)["AccessKey"]
        new_id = new_key["AccessKeyId"]
        new_secret = new_key["SecretAccessKey"]

        details: dict[str, Any] = {
            "vendor_resource_id": f"rotated:old={old_key}:new={new_id}",
            "vendor_new_access_key_id": new_id,
            # SENSITIVE — runtimes MUST persist this through a secure
            # channel (Vault, AWS Secrets Manager, etc.) and SHOULD
            # NOT log details verbatim. The audit chain hashes the
            # row but does not encrypt fields ; logging discipline is
            # the runtime's responsibility.
            "vendor_secret_material": new_secret,
        }

        # Step 2 (opt-in safety): only delete the old key if the
        # config flag is on. Default is True (full rotation), but
        # production deployments often want to keep the old key
        # Active for a grace window so a distribution failure does
        # not lock the principal out.
        if self._delete_old_after_rotation:
            iam.delete_access_key(UserName=owner, AccessKeyId=old_key)
            details["vendor_old_key_deleted"] = True
        else:
            details["vendor_old_key_deleted"] = False
            details["vendor_advisory"] = (
                "old key kept Active per config['delete_old_after_rotation']=False ; "
                "issue a follow-up iam.credentials_disable on the old key after "
                "verifying the new credential works"
            )
        return details

    def _kms_set_state(
        self, spec: ResponseActionSpec, *, enabled: bool
    ) -> dict[str, Any]:
        assert self._session is not None
        kms = self._session.client("kms")
        if enabled:
            kms.enable_key(KeyId=spec.subject.selector_value)
            verb = "enabled"
        else:
            kms.disable_key(KeyId=spec.subject.selector_value)
            verb = "disabled"
        return {
            "vendor_resource_id": f"kms_{verb}:{spec.subject.selector_value}",
        }

    def _kms_rotate_now(self, spec: ResponseActionSpec) -> dict[str, Any]:
        """Force an immediate KMS key rotation.

        Uses ``RotateKeyOnDemand`` (available on symmetric CMKs since
        2023). This creates a new backing key version *now* — old
        versions remain enabled for decrypt, so consumers caching the
        old version are NOT broken (the AWS KMS contract is
        version-add). EnableKeyRotation, by contrast, only toggles
        the future annual auto-rotation — that's the wrong primitive
        for an IR rotation.
        """
        assert self._session is not None
        kms = self._session.client("kms")
        resp = kms.rotate_key_on_demand(KeyId=spec.subject.selector_value)
        rotation_id = resp.get("KeyId", spec.subject.selector_value)
        return {
            "vendor_resource_id": f"kms_rotated:{rotation_id}",
        }

    def _kms_schedule_deletion(self, spec: ResponseActionSpec) -> dict[str, Any]:
        assert self._session is not None
        kms = self._session.client("kms")
        # cooldown_days validated by the runner (canonical schema
        # asserts integer 1-90) ; AWS clamps further to 7-30. The
        # connector clamps and surfaces the effective value.
        requested = int(spec.params["cooldown_days"])
        effective = max(7, min(30, requested))
        resp = kms.schedule_key_deletion(
            KeyId=spec.subject.selector_value,
            PendingWindowInDays=effective,
        )
        delete_at = resp.get("DeletionDate")
        return {
            "vendor_resource_id": f"kms_deletion_scheduled:{spec.subject.selector_value}",
            "vendor_cooldown_days": effective,
            "vendor_cooldown_clamped": effective != requested,
            "vendor_delete_at": str(delete_at) if delete_at else None,
        }

    def _s3_bucket_lockdown(self, spec: ResponseActionSpec) -> dict[str, Any]:
        assert self._session is not None
        s3 = self._session.client("s3")
        bucket = spec.subject.selector_value
        # Step 1 : block all public access at the bucket level.
        s3.put_public_access_block(
            Bucket=bucket,
            PublicAccessBlockConfiguration={
                "BlockPublicAcls": True,
                "IgnorePublicAcls": True,
                "BlockPublicPolicy": True,
                "RestrictPublicBuckets": True,
            },
        )
        # Step 2 : layer a deny policy. The connector preserves any
        # existing policy via the orchestrator's prior knowledge —
        # this reference does NOT do "merge with existing" and
        # documents that limitation explicitly.
        deny_policy = {
            "Version": "2012-10-17",
            "Statement": [
                {
                    "Sid": "WarlogLockdownDenyAll",
                    "Effect": "Deny",
                    "Principal": "*",
                    "Action": "s3:*",
                    "Resource": [
                        f"arn:aws:s3:::{bucket}",
                        f"arn:aws:s3:::{bucket}/*",
                    ],
                }
            ],
        }
        s3.put_bucket_policy(Bucket=bucket, Policy=json.dumps(deny_policy))
        return {
            "vendor_resource_id": f"s3_locked:{bucket}",
        }

    def _s3_bucket_unlock(self, spec: ResponseActionSpec) -> dict[str, Any]:
        """Remove the lockdown imposed by ``_s3_bucket_lockdown``.

        This is intentionally conservative : it removes the
        ``WarlogLockdownDenyAll`` deny policy and the public-access
        block, but does NOT restore any prior bucket policy that
        existed before lockdown — the orchestrator is responsible
        for re-applying its desired policy explicitly. Treating
        unlock as "remove the lockdown artifacts" rather than
        "restore prior state" keeps the audit chain unambiguous.
        """
        assert self._session is not None
        s3 = self._session.client("s3")
        bucket = spec.subject.selector_value
        try:
            s3.delete_bucket_policy(Bucket=bucket)
        except Exception:  # noqa: BLE001
            # If no policy was set, AWS returns NoSuchBucketPolicy ;
            # treat as already-clean rather than a hard error.
            pass
        try:
            s3.delete_public_access_block(Bucket=bucket)
        except Exception:  # noqa: BLE001
            pass
        return {
            "vendor_resource_id": f"s3_unlocked:{bucket}",
            "vendor_advisory": (
                "unlock removes the lockdown artifacts but does NOT restore "
                "any prior bucket policy ; orchestrator must re-apply desired policy"
            ),
        }

    def _ec2_state(
        self, spec: ResponseActionSpec, *, action: str
    ) -> dict[str, Any]:
        assert self._session is not None
        ec2 = self._session.client("ec2")
        instance_id = spec.subject.selector_value
        if action == "stop":
            ec2.stop_instances(
                InstanceIds=[instance_id],
                Hibernate=bool(spec.params.get("hibernate", False)),
            )
        elif action == "start":
            ec2.start_instances(InstanceIds=[instance_id])
        elif action == "terminate":
            ec2.terminate_instances(InstanceIds=[instance_id])
        else:
            raise ConnectorAbiError(
                FailureCategory.POLICY,
                f"aws: unknown EC2 action {action!r}",
            )
        return {"vendor_resource_id": f"ec2_{action}:{instance_id}"}

    # -- Verify reads ----------------------------------------------------

    def _verify_state(self, spec: ResponseActionSpec) -> bool:
        assert self._session is not None
        if spec.action_id is ResponseActionId.IAM_CREDENTIALS_DISABLE:
            return self._iam_credentials_status_is(spec, "Inactive")
        if spec.action_id is ResponseActionId.IAM_CREDENTIALS_ENABLE:
            return self._iam_credentials_status_is(spec, "Active")
        if spec.action_id is ResponseActionId.KEY_DISABLE:
            return self._kms_state_is(spec, "Disabled")
        if spec.action_id is ResponseActionId.KEY_ENABLE:
            return self._kms_state_is(spec, "Enabled")
        if spec.action_id is ResponseActionId.KEY_ROTATE:
            # No idempotent "rotation happened" GET ; the apply 2xx
            # is the contract. AWS does expose ListKeyRotations to
            # check rotation history but the on-demand timestamp
            # comparison is racy ; trust apply.
            return True
        if spec.action_id is ResponseActionId.BUCKET_LOCKDOWN:
            return self._bucket_is_locked(spec)
        if spec.action_id is ResponseActionId.BUCKET_UNLOCK:
            return not self._bucket_is_locked(spec)
        if spec.action_id is ResponseActionId.HOST_STOP:
            return self._ec2_state_is(spec, ("stopping", "stopped"))
        if spec.action_id is ResponseActionId.HOST_START:
            return self._ec2_state_is(spec, ("pending", "running"))
        if spec.action_id is ResponseActionId.IAM_ROLE_DETACH:
            return not self._iam_role_attached(spec)
        if spec.action_id is ResponseActionId.IAM_ROLE_ATTACH:
            return self._iam_role_attached(spec)
        return False

    def _iam_credentials_status_is(
        self, spec: ResponseActionSpec, expected: str
    ) -> bool:
        assert self._session is not None
        iam = self._session.client("iam")
        owner = spec.params["principal_id"]
        keys = iam.list_access_keys(UserName=owner).get("AccessKeyMetadata", [])
        target = spec.subject.selector_value
        for k in keys:
            if k["AccessKeyId"] == target:
                return k["Status"] == expected
        return False

    def _kms_state_is(self, spec: ResponseActionSpec, expected: str) -> bool:
        assert self._session is not None
        kms = self._session.client("kms")
        meta = kms.describe_key(KeyId=spec.subject.selector_value)["KeyMetadata"]
        return meta.get("KeyState") == expected

    def _bucket_is_locked(self, spec: ResponseActionSpec) -> bool:
        assert self._session is not None
        s3 = self._session.client("s3")
        try:
            pab = s3.get_public_access_block(Bucket=spec.subject.selector_value)
        except Exception:  # noqa: BLE001
            return False
        cfg = pab.get("PublicAccessBlockConfiguration") or {}
        return all(
            cfg.get(k) is True
            for k in (
                "BlockPublicAcls",
                "IgnorePublicAcls",
                "BlockPublicPolicy",
                "RestrictPublicBuckets",
            )
        )

    def _ec2_state_is(
        self, spec: ResponseActionSpec, allowed: tuple[str, ...]
    ) -> bool:
        assert self._session is not None
        ec2 = self._session.client("ec2")
        resp = ec2.describe_instances(InstanceIds=[spec.subject.selector_value])
        for res in resp.get("Reservations", []):
            for inst in res.get("Instances", []):
                state = (inst.get("State") or {}).get("Name")
                if state in allowed:
                    return True
        return False

    def _iam_role_attached(self, spec: ResponseActionSpec) -> bool:
        assert self._session is not None
        iam = self._session.client("iam")
        policy_arn = spec.params["policy_id"]
        principal = spec.subject.selector_value
        if spec.subject.selector_type == "iam_user":
            attached = iam.list_attached_user_policies(UserName=principal)
        else:
            attached = iam.list_attached_role_policies(RoleName=principal)
        return any(
            p.get("PolicyArn") == policy_arn
            for p in attached.get("AttachedPolicies", [])
        )

    async def aclose(self) -> None:
        # boto3 sessions don't require explicit close.
        return


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

_SUPPORTED: frozenset[ResponseActionId] = frozenset(
    {
        ResponseActionId.HOST_STOP,
        ResponseActionId.HOST_START,
        ResponseActionId.HOST_DELETE,
        ResponseActionId.IAM_ROLE_DETACH,
        ResponseActionId.IAM_ROLE_ATTACH,
        ResponseActionId.IAM_CREDENTIALS_DISABLE,
        ResponseActionId.IAM_CREDENTIALS_ENABLE,
        ResponseActionId.IAM_CREDENTIALS_ROTATE,
        ResponseActionId.KEY_DISABLE,
        ResponseActionId.KEY_ENABLE,
        ResponseActionId.KEY_ROTATE,
        ResponseActionId.KEY_SCHEDULE_DELETION,
        ResponseActionId.BUCKET_LOCKDOWN,
        ResponseActionId.BUCKET_UNLOCK,
    }
)


# AWS error codes → FailureCategory. boto3 surfaces these as
# ``ClientError.response['Error']['Code']`` strings.
_AWS_ERROR_CATEGORY: dict[str, tuple[FailureCategory, bool]] = {
    "AccessDenied": (FailureCategory.AUTH, False),
    "AccessDeniedException": (FailureCategory.AUTH, False),
    "InvalidClientTokenId": (FailureCategory.AUTH, False),
    "ExpiredToken": (FailureCategory.AUTH, False),
    "UnauthorizedOperation": (FailureCategory.POLICY, False),
    "NoSuchEntity": (FailureCategory.NOT_FOUND, False),
    "NoSuchBucket": (FailureCategory.NOT_FOUND, False),
    "NoSuchKey": (FailureCategory.NOT_FOUND, False),
    "InvalidInstanceID.NotFound": (FailureCategory.NOT_FOUND, False),
    "DeleteConflict": (FailureCategory.STATE_CONFLICT, False),
    "EntityAlreadyExists": (FailureCategory.STATE_CONFLICT, False),
    "ConditionalCheckFailedException": (FailureCategory.STATE_CONFLICT, False),
    "Throttling": (FailureCategory.TRANSIENT, True),
    "RequestLimitExceeded": (FailureCategory.TRANSIENT, True),
    "ServiceUnavailable": (FailureCategory.TRANSIENT, True),
}


def _map_aws_error(exc: Exception, *, op: str) -> ConnectorAbiError:
    """Map a boto3 error to a categorized ABI error."""
    try:
        from botocore.exceptions import ClientError  # type: ignore[import-not-found]
    except ImportError:
        return ConnectorAbiError(
            FailureCategory.TRANSIENT,
            f"aws {op} failed (boto3 not available): {exc}",
        )
    if isinstance(exc, ClientError):
        err = exc.response.get("Error", {})
        code = err.get("Code", "Unknown")
        message = err.get("Message", str(exc))
        category, retryable = _AWS_ERROR_CATEGORY.get(
            code, (FailureCategory.POLICY, False)
        )
        return ConnectorAbiError(
            category,
            f"aws {op} failed: {code}",
            retryable=retryable,
            vendor_code=code,
            vendor_message=message[:200],
        )
    return ConnectorAbiError(
        FailureCategory.TRANSIENT,
        f"aws {op} failed: {exc}",
        retryable=True,
    )


def _cached_success(
    spec: ResponseActionSpec, *, vendor_resource_id: str
) -> ResponseActionResult:
    """Build the dedup'd result for a repeat apply with the same key.

    Note : the original sensitive details (e.g. credentials_rotate's
    secret_material) are intentionally NOT replayed on the dedup
    path — the runtime is supposed to have persisted them on the
    first call. Replay would invite duplicate distribution.
    """
    return ResponseActionResult(
        execution_id="",
        action_id=spec.action_id,
        outcome=ExecutionOutcome.SUCCESS,
        subject=spec.subject,
        details={"vendor_resource_id": vendor_resource_id, "vendor_dedup": True},
    )


# ---------------------------------------------------------------------------
# CLI walkthrough — capability inspection only.
# ---------------------------------------------------------------------------


async def _main() -> None:
    cap = AwsResponseConnector.capability
    print(f"connector_id     = {cap.connector_id}")
    print(f"connector_version= {cap.connector_version}")
    print(f"vendor           = {cap.vendor}")
    print(f"kind             = {cap.kind.value}")
    print(f"auth_model       = {cap.auth.model.value}")
    print(f"actions          = {[a.value for a in cap.egress.supports_response_actions]}")
    print(f"dry_run.scope    = {cap.dry_run.scope.value}")
    print()
    print("To exercise against a real AWS account :")
    print("  pip install boto3")
    print("  aws configure  # or set AWS_PROFILE / instance profile")
    print("  python -m examples.aws_response_connector --live")


if __name__ == "__main__":
    asyncio.run(_main())
