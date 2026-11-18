# Use case: a cloud coding agent works on a remote test, development or build device

A coding agent running in a cloud container installed a signed software release on a remote
device, then ran its benchmarks. The device could just as well be a test rig, a developer box or
a build machine. The agent had no network path to it. Every command
went through the HaiveControl hub, and a person approved each step that changed the device.

## The problem

Coding agents increasingly run in the cloud, but the code they write often has to be installed,
built or measured on a specific machine: a test rig, a developer's box, a build server, hardware
on a desk. Getting the agent there has been a bad choice between two options:

- **Give the agent access:** an SSH key, a VPN or an open port. It then has standing root on the
  machine, nobody sees each command before it runs, and the credential outlives the task.
- **Keep a person in the loop by hand:** the agent writes commands, a person copies them to a
  terminal and pastes the output back. It's safe, but slow, error-prone and hard to audit.

And the machines are usually behind NAT or a firewall, where an inbound connection from the
cloud isn't possible anyway.

## The setup

| Part | Where it runs | What it does |
|---|---|---|
| Coding agent | a cloud container | writes the scripts, sends commands, reads results |
| HaiveControl hub | a server both sides can reach | classifies each command, holds it for approval, records the result |
| `haive-agent` relay | the device | runs what the hub releases to it and sends the output back |
| A person | the hub's dashboard | sees the exact command text and approves or rejects it |

The device only makes an outbound connection to the hub. Nothing on the device listens for the
agent, and the agent holds no SSH key or VPN access.

## One command, step by step

1. **The agent sends the command** to the hub's exec endpoint, naming the device as the target
   and authenticating with its hub token.
2. **The hub classifies it.**
   - A read-only command on the hub's allowlist (`tail`, `cat`, `ls`, `ps`) runs at once, and its
     output comes back in the same reply. This is how the agent follows install logs without
     asking anyone.
   - Everything else is held: pipes, redirection, `$(...)` substitution, background jobs, and any
     program not on the list. The hub answers `PENDING` with an approval ID (`apr_...`) and a
     reason. Nothing has run on the device yet.
3. **A person decides** in the dashboard, seeing the exact command text. A pending request
   expires after one hour.
4. **The hub runs it once.** The relay runs the command at the privileged tier. The hub records
   who approved it and when, the job ID, the exit code and the output.
5. **The agent fetches the result** by approval ID: status, exit code and output. Sending the
   same command again does not reuse an approval; it files a new request with a new ID.

## How the work was shaped to keep approvals few

- **A whole stage is one approval.** Each stage (install, then benchmarks) is one script written
  by the agent. It is base64-encoded, so no shell quoting reaches the hub's classifier, and sent
  as one command. That command decodes the script on the device and starts it detached
  (`setsid nohup`), so the hub call returns at once instead of timing out on a long build.
- **Progress is read for free.** Each script writes its own log on the device, and the agent reads
  it with `tail`, which is on the allowlist and needs no approval.
- **The scripts check before acting.** The install stage verifies the release package against the
  project's published signing key and stops if the check fails. The benchmark stage waits for
  the install stage to write its final line.

## The value

- **The agent works where the code really runs,** with no inbound access to the machine and no
  key handed over.
- **A person decides every change and sees its exact text,** without copying, pasting or
  relaying output.
- **Reading is free:** logs and status need no approval, so the agent follows long builds itself.
- **An audit trail comes for free:** each change has an approver, a time, an exit code and output.

## Limits we hit

- **Command size:** one command is capped at about 128 KB, so a large test set could not travel in
  a single request.
- **Repeats cost approvals:** every repeat of a held command needs a fresh approval. Accidental
  duplicates show up as extra pending requests, and the person rejects them.

## Security notes

- **Least standing access:** the agent can read without asking, but it can change nothing on the
  device without a person seeing the exact command first.
- **Every change has a record:** each one has an approver, a time, an exit code and the output.
- **The token:** keep the hub token out of the repository, use a per-agent token rather than a
  shared one, and rotate it when the work ends.
- **Root:** approved commands run as root, so the scripts confine themselves to one working
  directory on the device. Any cleanup outside it is a separate, explicitly approved step.
