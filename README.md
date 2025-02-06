# SBOM VEX Analyzer PoC

This repository demonstrates a proof-of-concept (PoC) implementation of analyzing Software Bill of Materials (SBOM) using VEX (Vulnerability Exploitability eXchange) data.

⚠️ **IMPORTANT**: This is a proof-of-concept implementation. Please carefully evaluate before using in production environments.

## Overview

This PoC shows how to:
- Generate SBOM from container images using Syft
- Analyze vulnerabilities using VEX data
- Process CycloneDX JSON format SBOMs

## Prerequisites

- Python 3.x (Tested in Python 3.13.1)
- [Syft](https://github.com/anchore/syft) - for SBOM generation
- Access to container registries

## Usage

### 1. Generate SBOM

First, generate the SBOM using Syft:

```bash
syft registry.access.redhat.com/ubi8/openjdk-17:1.20-2.1729094551 -o cyclonedx-json > openjdk-17-1.20-sbom.json
```

### 2. Run the Analyzer

Execute the VEX analyzer with the generated SBOM:

```bash
python3 vex_analyzer.py openjdk-17-1.20-sbom.json cve-vex
```

## Demo Container Image

This demo uses the Red Hat Universal Base Image (UBI 8) with OpenJDK 17:

- **Image**: `registry.access.redhat.com/ubi8/openjdk-17:1.20-2.1729094551`
- **Details**: [Red Hat Container Catalog](https://catalog.redhat.com/software/containers/ubi8/openjdk-17/618bdbf34ae3739687568813?image=670fe9d16918e2002b32af33)

## Limitations

- This is a proof-of-concept implementation
- Limited error handling
- May not cover all edge cases
- Not recommended for production use without proper evaluation and enhancement

## Contributing

Feel free to open issues and pull requests for improvements.
