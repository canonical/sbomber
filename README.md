# Setup

Connect to the canonical VPN

    sudo snap install astral-uv
    sudo snap install canonical-security-scan

    chmod +x sbomber
    sh ./sbomber


# Using SBOMber

The main use case of sbomber is a centralized CI runner that periodically runs security-related routine tasks 
on a bunch of charms, snaps, rocks... We call all of those 'artifacts' for short.

The focus here is on parallelism, as many teams have tens of artifacts they need to verify and doing that 
manually or sequentially will take time.

Therefore, the tool splits the workflow into steps and keeps them in sync using a filesystem-based state file:
- collect all artifacts into a single place
- upload each artifact and obtain a unique identifier, or token, for it
- query the report generation status for each artifact
- download all reports (if they are ready)

This is what we call the `parallel` workflow.

## Prepare a manifest

Write to `./sbom_manifest.yaml` a specification of the packages for which you want to request security reports.

```yaml
clients: 
  - sbom: 
      department: charming_engineering
      email: luca.bello@canonical.com  # revenge is a dish best served cold
      team: observability
  - secscan: {}
  
artifacts:
  - name: parca-k8s
    revision: 299
    type: charm

  - name: jhack
    type: snap

  - name: /home/pietro/canonical/parca-k8s-operator/parca-k8s_ubuntu@24.04-amd64.charm
    type: local
```


### Configuring the clients

Want to only request sboms? Omit `secscan` from the clients.
Want to skip sboms? Only include `secscan`.

Want to override on a per-artifact basis what client(s) they will use?

```yaml
clients: 
  - sbom: 
      department: charming_engineering
      email: luca.bello@canonical.com  # revenge is a dish best served cold
      team: observability
  - secscan: {}
  
  
artifacts:
  - name: parca-k8s
    revision: 299
    type: charm
    clients: ['sbom']  # only sbom; no secscan

  - name: jhack
    type: snap
    clients: ['secscan']  # only secscan; no sbom

  - name: /home/pietro/canonical/parca-k8s-operator/parca-k8s_ubuntu@24.04-amd64.charm
    type: local
    # default: use all clients
```


## Fetch all packages and prepare the artifacts

> sbomber prepare

This will download the remote artifacts and copy the local ones to `./pkgs`, preparing them for upload.
The state will be saved in `./.statefile.yaml`.


## Submit the artifacts

> sbomber submit

This will upload the artifacts to the respective clients and verify the upload.

## Poll for status

This will update the statefile with the status for each artifact, as reported by the service. 
> sbomber poll

Alternatively, you can block and wait for all artifacts to be ready:

> sbomber poll --wait --timeout 30  

NB: The timeout is in minutes, and applies to each artifact.


## Download all SBOMs

> sbomber download
 
This will download all ready artifacts to `./sbombs`


## Additional configuration options

Check the CLI help for more parameters and options.


# Using the end to end sequential workflow

There is also an "end to end" workflow exposed by the `sbomber sequential [sbom|secscan]` commands, 
which will fetch and upload the artifact, wait for all reports to be ready and download them in a 
blocking fashion, rendering the statefile unnecessary.

This is handy to integrate in individual artifact-generating CIs, e.g. to run the tool every time a new version is released.
