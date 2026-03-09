# Demo Guide

This is the simplified guide for a quick try-on and demonstrations. It's not suitable for production deployments
nor getting a broader understanding of the TinyPKI ecosystem.

## Prerequisites

1. Install [Docker Engine](https://docs.docker.com/engine/install/)
2. Install [Step CLI](https://github.com/smallstep/cli/releases)

## Installation

1. Clone this repository:
   ```
   git clone git@github.com:icedevml/tinypki.git
   ```

2. Prepare the `env/` directory and pre-seed all secrets:
   ```
   python3 makeenv.py
   ```

3. Launch TinyPKI:
   ```
   docker compose up --build
   ```

## Configuration

1. In the project's root directory, run:
   ```
   ./onboard.sh
   ```
2. Install `ca_roots.pem` in your browser/system as a trusted CA.
3. Install `step.p12` (password: `admin`) in your browser/system as a client certificate/key.
4. Execute the following to bind `tinypki.home` to localhost:
   ```
   sudo sh -c 'echo "127.0.0.1 tinypki.home" >> /etc/hosts'
   ```
5. Visit https://tinypki.home:9443/ for the TinyPKI web dashboard.
6. Go to "Provisioners" -> "Add provisioner" and enter the details displayed by the script from the step 2.
7. Go to "Blueprints" -> "Create blueprint" and choose your desired configuration (you can just leave the defaults).
8. Now your TinyPKI instance is fully functional.
