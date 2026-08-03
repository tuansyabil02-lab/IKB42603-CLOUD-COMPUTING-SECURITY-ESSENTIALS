# Lab 1: Cloud Account Security, Identity and Access Management

**Course:** IKB42603 Cloud Computing Security Essentials
**Lab:** Lab 1
**Topic:** Identity governance, least privilege, LocalStack IAM and Kubernetes RBAC
**Environment:** LocalStack on `localhost:4566` and kind Kubernetes cluster `ccse-lab1`
<br> **Name:** Student Name

## Lab Summary // Objective

This lab explored how account-level security and access control can be enforced using two local platforms:

- **LocalStack IAM**, which simulates AWS IAM users, groups, policies and access keys without touching a real AWS account.
- **Kubernetes RBAC**, which was used to enforce genuine authorization decisions through roles and role bindings on a local `kind` cluster.

## Evidence Folder

All screenshots referenced in this report are stored in the `Evidence` folder.

| Evidence File | Purpose |
|---|---|
| `0-Caller-Identity.png` | Confirms the AWS CLI is targeting LocalStack via `sts get-caller-identity` |
| `1-Group-Creation.png` | `Admins` group creation output |
| `2-Group-Policy-Attach.png` | Confirms `AdministratorAccess` is attached to the `Admins` group |
| `3-CloudAdmin-Creation.png` | Creation output for the admin user `CloudAdmin_bil` |
| `4-Verify-Membership.png` | Confirms `CloudAdmin_bil` is listed as a member of the `Admins` group |
| `5-Analyst-Creation.png` | Creation output for the read-only user `Analyst_bil` |
| `6-ListPermission-User.png` | Confirms `AmazonS3ReadOnlyAccess` is attached to `Analyst_bil` |
| `7-Access-Key.png` | Access key generated for `Analyst_bil` |
| `8-List-Access-Keys.png` | Access key listing for `Analyst_bil` |
| `9-Key-Rotation.png` | Command used to deactivate the `Analyst_bil` access key |
| `10-SessionB-Setup.png` | Local `kind` Kubernetes cluster creation and node status |
| `11-Env-Namespace.png` | Creation of the `dev` and `prod` namespaces |
| `12-Role-Bind.png` | Service account, Role and RoleBinding creation |
| `13-RBAC-Test.png` | Results of the `kubectl auth can-i` authorization tests |
| `14-Verification-RBAC.png` | YAML output confirming the RoleBinding configuration |

## Task 1: Map the Cloud Identity Landscape

| Concept | AWS Term | Purpose |
|---|---|---|
| All-powerful owner | Root user | The original account owner with unrestricted access to every resource and to billing. It is meant to be locked away and kept out of everyday use. |
| Human/app identity | IAM User | A named identity representing a person, application or service that holds credentials for accessing cloud resources. |
| Permission bundle | IAM Policy | A JSON document specifying which actions are permitted or denied against particular resources. |
| Collection of users | IAM Group | A container used to manage shared permissions by attaching policies once at the group level. |
| Temporary identity | IAM Role | An identity that can be assumed for a limited time to obtain short-lived permissions instead of relying on permanent credentials. |

## Session A: LocalStack IAM

### Environment Setup

The AWS CLI was configured to target LocalStack rather than real AWS by exporting the endpoint as a variable:

```bash
EP='--endpoint-url=http://localhost:4566'
```

This ensured every subsequent `aws` command was routed to the local LocalStack service.

Verification command:

```bash
aws --endpoint-url=http://localhost:4566 sts get-caller-identity
```

Output:

```json
{
    "UserId": "AKIAIOSFODNN7EXAMPLE",
    "Account": "000000000000",
    "Arn": "arn:aws:iam::000000000000:root"
}
```

The placeholder account ID `000000000000` confirms all activity took place inside LocalStack, not a live AWS account.

Evidence:

![Caller identity verification](Evidence/0-Caller-Identity.png)

## Task 2: Create a Least-Privilege Admin

### Step 2.1: Create the Admins Group and Attach the Administrator Policy

Commands:

```bash
aws $EP iam create-group --group-name Admins

aws $EP iam attach-group-policy --group-name Admins \
    --policy-arn arn:aws:iam::aws:policy/AdministratorAccess
```

Result:

The `Admins` group was created and the AWS-managed `AdministratorAccess` policy was attached to it, so any user placed inside this group automatically inherits full administrative rights.

Verification command:

```bash
aws $EP iam list-attached-group-policies --group-name Admins
```

Output:

```json
{
    "AttachedPolicies": [
        {
            "PolicyName": "AdministratorAccess",
            "PolicyArn": "arn:aws:iam::aws:policy/AdministratorAccess"
        }
    ]
}
```

Evidence:

![Admins group creation](Evidence/1-Group-Creation.png)
![AdministratorAccess policy attached to Admins](Evidence/2-Group-Policy-Attach.png)

### Step 2.2: Create the Personal Admin User

Command:

```bash
aws $EP iam create-user --user-name CloudAdmin_bil
```

Output:

```json
{
    "User": {
        "Path": "/",
        "UserName": "CloudAdmin_bil",
        "UserId": "1a5ly91489a57ri41kid",
        "Arn": "arn:aws:iam::000000000000:user/CloudAdmin_bil",
        "CreateDate": "2026-08-03T01:12:15.156000+00:00"
    }
}
```

Evidence:

![CloudAdmin user creation](Evidence/3-CloudAdmin-Creation.png)

### Step 2.3: Add the User to the Admins Group and Verify Membership

Command:

```bash
aws $EP iam add-user-to-group --group-name Admins \
    --user-name CloudAdmin_bil
```

Verification command:

```bash
aws $EP iam get-group --group-name Admins
```

Output:

```json
{
    "Users": [
        {
            "Path": "/",
            "UserName": "CloudAdmin_bil",
            "UserId": "1a5ly91489a57ri41kid",
            "Arn": "arn:aws:iam::000000000000:user/CloudAdmin_bil",
            "CreateDate": "2026-08-03T01:12:15.156000+00:00"
        }
    ],
    "Group": {
        "Path": "/",
        "GroupName": "Admins",
        "GroupId": "zhahlojypzuvdquh57ad",
        "Arn": "arn:aws:iam::000000000000:group/Admins",
        "CreateDate": "2026-08-03T01:04:55.849000+00:00"
    }
}
```

This confirms `CloudAdmin_bil` belongs to the `Admins` group, meaning administrative access comes from group membership rather than a policy attached straight to the user.

Evidence:

![Verify Admins membership](Evidence/4-Verify-Membership.png)

## Task 3: Enforce Least Privilege with a Scoped Policy

### Step 3.1: Create the Read-Only Analyst User

Command:

```bash
aws $EP iam create-user --user-name Analyst_bil
```

Output:

```json
{
    "User": {
        "Path": "/",
        "UserName": "Analyst_bil",
        "UserId": "kdrmv8388e0wu2zxe1uf",
        "Arn": "arn:aws:iam::000000000000:user/Analyst_bil",
        "CreateDate": "2026-08-03T01:14:01.089000+00:00"
    }
}
```

Evidence:

![Analyst user creation](Evidence/5-Analyst-Creation.png)

### Step 3.2: Attach the S3 Read-Only Policy

Command:

```bash
aws $EP iam attach-user-policy --user-name Analyst_bil \
    --policy-arn arn:aws:iam::aws:policy/AmazonS3ReadOnlyAccess
```

### Step 3.3: Verify Analyst Permissions

Verification command:

```bash
aws $EP iam list-attached-user-policies --user-name Analyst_bil
```

Output:

```json
{
    "AttachedPolicies": [
        {
            "PolicyName": "AmazonS3ReadOnlyAccess",
            "PolicyArn": "arn:aws:iam::aws:policy/AmazonS3ReadOnlyAccess"
        }
    ]
}
```

The output shows that `Analyst_bil` carries only the `AmazonS3ReadOnlyAccess` policy and nothing broader.

Evidence:

![Analyst read-only policy](Evidence/6-ListPermission-User.png)

### Least Privilege Explanation

- Should the `Analyst_bil` credentials ever leak, the fallout would stay contained because the account can only read S3 data.
- There is no path to administrative actions — an attacker with this identity could not spin up new users, remove resources, rewrite IAM policy, or alter stored data.
- Scoping the account this tightly shrinks the blast radius to whatever a read-only S3 session could expose.

## Task 4: Credential Hygiene and Access Keys

### Step 4.1: Create an Access Key

Command:

```bash
aws $EP iam create-access-key --user-name Analyst_bil
```

Result:

An access key pair was generated for `Analyst_bil`.

Evidence:

![Access key creation](Evidence/7-Access-Key.png)

Security note: the secret access key value has been withheld from this report. In production environments, access keys should never be committed to a repository, pasted into a screenshot, or stored as plain text.

### Step 4.2: List Access Keys

Command:

```bash
aws $EP iam list-access-keys --user-name Analyst_bil
```

Output:

```json
{
    "AccessKeyMetadata": [
        {
            "UserName": "Analyst_bil",
            "AccessKeyId": "LKIAQAAAAAAANJLMOM4U",
            "Status": "Active",
            "CreateDate": "2026-08-03T01:15:36+00:00"
        }
    ]
}
```

Evidence:

![Access key listing](Evidence/8-List-Access-Keys.png)

### Step 4.3: Rotate and Deactivate the Key

Command:

```bash
aws $EP iam update-access-key --user-name Analyst_bil \
    --access-key-id LKIAQAAAAAAANJLMOM4U --status Inactive
```

Result:

The key `LKIAQAAAAAAANJLMOM4U` was switched to `Inactive`, demonstrating the rotation/deactivation step that credential hygiene practices require once a key is no longer needed or is suspected of exposure.

Evidence:

![Access key deactivation command](Evidence/9-Key-Rotation.png)

## Session B: Kubernetes RBAC

### Setup: Create the Local Kubernetes Cluster

Commands:

```bash
kind create cluster --name ccse-lab1
kubectl cluster-info --context kind-ccse-lab1
kubectl get nodes
```

Result:

A local `kind` cluster named `ccse-lab1` was provisioned, `kubectl` was pointed at the `kind-ccse-lab1` context, and the control-plane node came up and registered.

Evidence:

![Session B cluster setup](Evidence/10-SessionB-Setup.png)

## Task 5: Separate Environments with Namespaces

Commands:

```bash
kubectl create namespace dev
kubectl create namespace prod
kubectl get namespaces
```

Result:

Both the `dev` and `prod` namespaces were created and appear with `Active` status alongside the cluster's default namespaces.

Evidence:

![Namespace creation](Evidence/11-Env-Namespace.png)

## Task 6: Define a Role and Bind It

### Step 6.1: Create the Service Account

Command:

```bash
kubectl create serviceaccount dev-user -n dev
```

Result:

The `dev-user` service account was created inside the `dev` namespace.

### Step 6.2: Create the Pod Reader Role

Command:

```bash
kubectl create role pod-reader -n dev \
    --verb=get,list,watch --resource=pods
```

Result:

The `pod-reader` Role was created in `dev`, granting only `get`, `list` and `watch` on pod resources.

### Step 6.3: Create the RoleBinding

Command:

```bash
kubectl create rolebinding dev-user-binding -n dev \
    --role=pod-reader --serviceaccount=dev:dev-user
```

Result:

`dev-user-binding` links the `pod-reader` Role to the `dev-user` service account.

Evidence:

![Role and RoleBinding creation](Evidence/12-Role-Bind.png)

## Task 7: Test Access Control

The service account identity was captured in a shell variable for reuse:

```bash
SA=system:serviceaccount:dev:dev-user
```

### Test 1: List Pods in Dev

Command:

```bash
kubectl auth can-i list pods -n dev --as=$SA
```

Result:

```text
yes
```

Explanation:

Listing succeeds because `pod-reader` explicitly grants the `list` verb on pods within `dev`, and the RoleBinding ties that Role to this service account.

### Test 2: Delete Pods in Dev

Command:

```bash
kubectl auth can-i delete pods -n dev --as=$SA
```

Result:

```text
no
```

Explanation:

Deletion is refused because `delete` was never included in the Role's verb list — only `get`, `list` and `watch` were granted.

### Test 3: List Pods in Prod

Command:

```bash
kubectl auth can-i list pods -n prod --as=$SA
```

Result:

```text
no
```

Explanation:

The Role and its binding exist only in `dev`, so RBAC has nothing to authorize this identity against in `prod` — the permission simply doesn't carry over between namespaces.

Evidence:

![RBAC can-i tests](Evidence/13-RBAC-Test.png)

### Authentication vs Authorization

Kubernetes first authenticates the caller as `system:serviceaccount:dev:dev-user` — that identity is recognized by the cluster. What happens next is a separate authorization check: listing pods in `dev` is approved because the RoleBinding grants it, while deleting pods in `dev` and listing pods in `prod` are both rejected because no rule ever authorized those specific actions.

## RBAC Verification Command

Required verification command:

```bash
kubectl get rolebinding dev-user-binding -n dev -o yaml
```

Output:

```yaml
apiVersion: rbac.authorization.k8s.io/v1
kind: RoleBinding
metadata:
  creationTimestamp: "2026-08-03T01:20:15Z"
  name: dev-user-binding
  namespace: dev
  resourceVersion: "565"
  uid: 9fad3d9b-251c-47cc-9d3b-e7635e350c59
roleRef:
  apiGroup: rbac.authorization.k8s.io
  kind: Role
  name: pod-reader
subjects:
- kind: ServiceAccount
  name: dev-user
  namespace: dev
```

Evidence:

![RoleBinding YAML verification](Evidence/14-Verification-RBAC.png)

This output confirms the exact wiring: `dev-user-binding` connects the `dev-user` service account to the `pod-reader` Role, scoped entirely to the `dev` namespace.

## Short-Answer Questions

### Q1. Why is attaching policies to groups better than attaching them directly to users?

Group-level policies centralize permission management. Instead of editing every individual user's permissions whenever access requirements change, an administrator updates the group once and every member's access shifts automatically. This lowers the chance of inconsistent permissions across users and makes audits far simpler, since reviewing one group policy tells you what an entire team can do.

### Q2. What is the difference between an IAM User and an IAM Role?

An IAM User is a persistent identity tied to a specific person or application, typically holding long-lived credentials like a password or access key that remain valid until someone manually revokes them. An IAM Role, by contrast, has no permanent credentials of its own — it is assumed on demand and issues temporary, expiring credentials. Roles are generally the safer choice for workloads and cross-account access because there's no standing secret sitting around waiting to be leaked.

### Q3. Explain least privilege using the Analyst account, and how it reduces blast radius if compromised.

`Analyst_bil` holds nothing beyond `AmazonS3ReadOnlyAccess`, so its entire capability set is limited to viewing objects in S3. Were these credentials stolen, the intruder inherits that same narrow scope — they could browse data but couldn't delete buckets, spin up new IAM identities, rewrite policies, or pivot into other services. Because the account was never granted more than it needed to do its job, a compromise of this identity translates into a small, containable incident rather than a full account takeover.

### Q4. In Kubernetes, what is the difference between a Role and a RoleBinding?

A Role is the permission definition — it lists which verbs (like `get`, `list`, `watch`) can be performed on which resources within a namespace, but on its own it applies to no one. A RoleBinding is what actually grants that Role to a subject, such as a service account or user. In this lab, `pod-reader` spells out what's allowed, and `dev-user-binding` is the piece that hands those allowances to `dev-user`.

### Q5. Why did the developer service account fail to access prod, and which security principle does that demonstrate?

The `dev-user` service account was never given a Role or RoleBinding inside the `prod` namespace — its only grant of permission lives in `dev`. Kubernetes RBAC evaluates authorization per namespace, so with nothing defined for `prod`, every request there is denied by default. This outcome illustrates least privilege paired with environment separation: identities are confined to the exact namespace they were provisioned for, preventing a development-scoped credential from ever touching production resources, intentionally or not.

## Security Best-Practices Checklist

- [x] Root user is kept out of daily operations; a dedicated admin identity, `CloudAdmin_bil`, handles administrative tasks instead.
- [x] Administrative rights flow through the `Admins` group rather than being attached directly to the admin user.
- [x] A least-privilege identity, `Analyst_bil`, was created and scoped to `AmazonS3ReadOnlyAccess` only.
- [x] Access keys were generated, listed, and later deactivated to demonstrate credential rotation.
- [x] Kubernetes RBAC correctly blocked unauthorized actions: pod deletion in `dev` and pod listing in `prod` were both denied.

## Conclusion

This lab put cloud identity management and least-privilege design into practice across two platforms. On the LocalStack side, administrative access was routed through a group rather than granted directly, while a separate analyst identity was locked down to read-only S3 access — and its access key lifecycle was exercised through creation, listing, and deactivation.

On the Kubernetes side, RBAC enforced a clean boundary around the `dev-user` service account: it could list pods in `dev`, but deletion in `dev` and any access to `prod` were both refused. Together, these results show authorization behaving exactly as least privilege and namespace isolation intend.
