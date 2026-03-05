# SafeProxy

SafeProxy is an advanced, multiclient proxy system featuring a dual-component architecture designed for secure web traffic monitoring, interception, and granular access control. 

Built with a focus on performance, security, and developer debuggability, SafeProxy handles dynamic HTTPS TLS termination via a custom Certificate Authority (CA), comprehensive connection tunneling, and custom real-time request injection.

## Project Purposes

* **Traffic Monitoring & Interception:** Deep inspection of HTTP/S traffic through dynamic TLS termination.
* **Access Control:** Granular blocklisting of specific hosts (e.g., `youtube.com/*`), explicit URLs (e.g., `youtube.com/video`), or specific IP addresses.
* **Privacy & Tunneling:** IP masking via raw TCP tunneling or standard HTTP proxying.
* **Secure Browsing Environment:** Operates entirely within an isolated, pre-configured Google Chrome environment to ensure the host machine's integrity remains intact.
* **Developer Debugging:** Offers meticulous, per-IP and per-host logging capabilities to easily trace network requests and identify anomalies.

---

## Features

### Server-Side Architecture
The backend is split into two distinct, highly optimized systems:

* **Proxy Server:**
    * **HTTPS TLS Termination:** Utilizes an optimized C-based SSL library for high-performance interception. Generates fake certificates on the fly using ECDSA keys for enhanced speed, with full fallback support for RSA.
    * **TCP Tunneling:** Supports secure HTTPS communication via TCP tunneling for traffic that should not be decrypted.
    * **Dynamic Access Rules & Custom Responses:** Blocks unauthorized or blacklisted traffic. Serves custom HTML error pages (403 Forbidden, 502 Bad Gateway) or dynamically redirects to a Google search for invalid hosts, based on client preferences.
    * **JWT Authentication:** Authenticates every single client request. The Proxy Server validates a JSON Web Token (JWT) injected into the HTTP headers using an ECDSA public key.
    * **Concurrency:** Fully multithreaded architecture capable of supporting thousands of parallel client connections efficiently.

* **Auth Server:**
    * **Custom Communication Protocol:** Utilizes a strict request/response enum-based protocol for predictable and secure data exchange (e.g., `cmdREQ` params, `RspStatus`).
    * **Secure Key Exchange:** Client-server communication is heavily encrypted using the Diffie-Hellman (DH) key exchange protocol and AES encryption.
    * **Database Management:** Powered by an integrated SQLite3 database storing hashed user credentials, tunneling preferences, and blocklist configurations.
    * **CA Certificate Updates:** Automatically manages and distributes updates to the Root CA to ensure all clients remain synced.

* **Sophisticated Logging System:**
    * **Thread-Local Context:** Generates dedicated log folders for every unique IP connected to the proxy.
    * **Per-Host Logs:** Individual log files are generated for each requested host, isolating request lifecycles for rapid debugging.
    * **Core System Logs:** `core.log` tracks top-level client connections and critical system states. `DB.log` monitors all Auth Server database transactions.

### Client-Side Architecture
The client software features a robust backend engine paired with a modern desktop UI:

* **Backend Client Engine:**
    * **Auth Handler:** Communicates with the upstream Auth Server for account management (login/signup/delete), preference synchronization, and blocklist updates.
    * **CA Certificate Management:** Verifies the integrity of the local Root CA against the server-side CA at the start of every session. Automatically prompts and installs the certificate to the local machine's trust store with administrative privileges if necessary.
    * **Inject Server:** A lightweight, local server that activates only upon successful authentication. It acts as the browser's immediate proxy, injecting the SafeProxy JWT authorization header into every outgoing request before forwarding it to the remote Proxy Server. It strategically opens new connections only for initial requests to preserve the server's IP-based logging integrity.

* **User Interface (UI):**
    * **Framework:** Built using Flet (v0.28.3) for a responsive and modern desktop experience.
    * **Views:** Includes Authentication (Login/Signup), Home Dashboard, Settings/Preferences, Account Management, and a dedicated CA Certificate status view to ensure proper local installation.
    * **Blocklist Management:** An interactive table view allowing users to add, delete, and annotate blacklisted hosts with custom reasoning.
    * **Browser Integration:** Automatically launches a dedicated, pre-connected Google Chrome instance pointing to the SafeProxy Inject Server upon toggling the connection.

---

## Architecture

The system operates on a segregated architecture to ensure performance and security:

Authentication Flow: The Client UI triggers the Auth Handler, which establishes a DH-exchanged AES-encrypted connection to the Server's Auth Server. Tokens (JWT) and preferences are exchanged and stored.

Proxy Flow: The user connects via the UI. The local Inject Server boots up. The UI spawns a Chrome browser routed to localhost:<inject_port>.

Request Lifecycle: The browser sends a request to the Inject Server. The Inject Server attaches the ECDSA-signed JWT and forwards it to the Remote Proxy Server. The Proxy Server validates the JWT, processes the blocklist rules, performs TLS interception (if enabled) by serving a dynamically generated certificate, fetches the remote data, and returns it through the tunnel.

```
CLIENT MACHINE                                 REMOTE SERVER SIDE
+---------------------------+                +---------------------------------------+
|  FLET UI (User Interface)  |                |          SAFEPROXY SERVER             |
|  [Preferences & Logs]     |                |                                       |
+------------+--------------+                +-------------------+-------------------+
             |                                                   |
             | (1) Auth & Config (DH + AES Encrypted)            |
             v                                                   v
+------------+--------------+                +-------------------+-------------------+
|    AUTH HANDLER           +<-------------->+      AUTH SERVER (SQLite DB)          |
| [Sync CA / Set Prefs]     |                |  [JWT Issuance / User Validation]     |
+------------+--------------+                +---------+---------+---------+---------+
             |                                         |         |         |
             | (2) Spawns on Connect                   |         |         |
             v                                         |         |         | (5) Log
+------------+--------------+                (4) JWT   |         |         |  Data
|   LOCAL INJECT SERVER     |     Auth       Validated |         |         |
| [Injects JWT Header]      +------------------------->+         |         |
+------------+--------------+   Request      +---------+---------+         |
             ^                               |   PROXY INTERCEPTOR       |         |
             |                               | [TLS Termination]   |         |
             | (3) Browser Traffic           | [Blacklist/URL Filter]    |         |
             |     (Localhost)               +---------+---------+---------+---------+
+------------+--------------+                          |                   |
|      CHROME BROWSER       |                          | (6) Request       | LOGGING
|  [Pre-configured Proxy]   |                          |     Forward       | SYSTEM
+---------------------------+                          v                   | (IP/Host
                                             +---------+---------+         |  Based)
                                             |   DESTINATION WEB |         |
                                             |   (Origin Server) |<--------+
                                             +-------------------+
```

---

## Project Structure

The repository is organized to clearly separate client logic, server logic, and security assets.

```text
├───.safeproxy
│   ├───jwt_keys                 # Public/Private keys for JWT signing and verification
│   └───root_ca                  # SafeProxy custom Root Certificate Authority
├───certs                        # Dynamically generated, host-specific certificates
├───src
│   ├───client                   # Client application root
│   │   ├───core                 # Client backend (Auth Handler, Inject Server, CA Check)
│   │   ├───logs                 # Client-side execution logs
│   │   ├───resources            # Local CA cert storage
│   │   └───ui                   # Flet UI views, fonts, and storage
│   └───server                   # Server application root
│       ├───auth_server          # Authentication and DB operations
│       ├───db                   # SQLite3 database storage
│       ├───logs                 # Granular proxy and DB logging
│       └───proxy                # Core TLS interception and TCP tunneling logic
├───venv                         # Python virtual environment containing all dependencies
```

---

## Quick Start & Installation

* **Prerequisites:** Python 3.12 or lower is strictly required because Flet 0.28.3 does not currently support Python 3.13.

### Server Setup
1. **Initialize the Virtual Environment:**
Navigate to the root directory and create the virtual environment:

```terminal
python -m venv venv
```

2. **Configure Environment Variables:**
Open the provided .env.example file. Set a strong password for your Root CA and define your proxy binding IP.

```terminal
# --- ROOT CA ---
ROOT_CA_PRIVATE_KEY_PASSWORD = your_strong_password_here # ENTER A PASSWORD TO KEEP ROOT CA'S PRIVATE KEY SAFE. [cite: 116]
ROOT_CA_DIR = ./.safeproxy/root_ca [cite: 117]

# --- NETWORK ---
PROXY_BIND = 127.0.0.1 [cite: 117]
PROXY_PORT = 2153 [cite: 117]
```

3. **Configure Server Constants:**
Open src/server/server_constants.py and ensure the constants match your environment requirements. Important constants include:
```terminal
PROXY_PORT = 2153
AUTH_SERVER_PORT = 2985
```

4. **Activate the Environment:**

```terminal
venv\Scripts\activate
```
5. **Install Dependencies:**

```terminal
pip install -r requirements.txt
```

6. **Run Server:**
Execute the server startup script from the root of the project:

```terminal
ServerSide.bat
```
(This batch script will automatically activate the virtual environment and start the Proxy and Auth servers).


### Client Setup
1. **Configure Client Constants:**
Open src/client/client_constants.py. You must change the proxy server IP to point to the machine hosting your server backend.

```terminal
PROXY_SERVER_IP = "127.0.0.1" # CRITICAL - CHANGE TO THE PROXY SERVER'S IP

# Default ports - ensure these stay the same.
PROXY_SERVER_PORT = 2153 
AUTH_SERVER_PORT = 2985
```
2. **Activate the Environment:**

```terminal
venv\Scripts\activate
```
3. **Install Dependencies:**

```terminal
pip install -r requirements.txt
```

4. **Run Client:**
Execute the client application from the root of the project:

```terminal
ClientSide.bat
```
(This batch script activates the existing virtual environment. It does not create it, so ensure step 1 of the Server Setup was completed on the client machine).

---

## Usage Examples
Starting a Session: After setting the server-side, Launch the client UI, register a new account, and log in. Navigate to the CA Certificate view to verify and install the Root CA.

Connecting: Toggle the connect button on the Home view. SafeProxy will launch an isolated Google Chrome instance perfectly configured to route traffic through the local Inject Server.

Managing Blocklists: In the UI, navigate to the blocklist table. Add a host (e.g., reddit.com) or a specific URL. Provide a reason in the UI for future reference. Attempting to navigate to this URL in the spawned browser will result in a custom SafeProxy error page.

Debugging Traffic: On the server machine, navigate to src/server/logs/output/clients/. Find the folder labeled with your IP address to view exact request/response lifecycles for every host visited.

---

## Libraries Used
* **Flet (flet==0.28.3):** Framework for the modern desktop GUI.
* **Cryptography:** Core library for dynamic certificate generation, ECDSA/RSA key management, and robust cryptographic operations.
* **PyJWT:** Secure creation, signing, and verification of JSON Web Tokens.
* **py-diffie-hellman:** Implementation of the Diffie-Hellman key exchange protocol for establishing secure communication channels with the Auth Server.
* **Yarl:** Advanced URL parsing and blocking analysis.
* **Python-dotenv:** Secure environment variable management.
* **Standard Python Libraries:** ssl (for the C-based secure sockets layer), sqlite3 (database operations), shutil (directory removal operations), and pathlib (path management).

---

## ⚠️ Security Disclaimer: Root CA Installation
**CRITICAL WARNING:** To enable HTTPS TLS interception, the SafeProxy client will prompt you to install a custom Root Certificate Authority (CA) onto your local machine's administrative trust store.

It is strictly your responsibility to keep the .safeproxy/root_ca private key entirely secure. If this private key is compromised, exposed, or uploaded to a public repository, malicious actors can generate perfectly trusted certificates for any domain (e.g., banking sites, email providers), opening your system to catastrophic Man-in-the-Middle (MITM) attacks. Never share, commit, or distribute your Root CA private key.

---

## Contributing
Contributions are what make the open-source community such an amazing place to learn, inspire, and create. Any contributions you make are greatly appreciated.

- Fork the Project
- Create your Feature Branch (`git checkout -b feature/AmazingFeature`)
- Commit your Changes (`git commit -m 'Add some AmazingFeature'`)
- Push to the Branch (`git push origin feature/AmazingFeature`)
- Open a Pull Request

If you found this proxy system helpful, please consider giving the repository a Star!

---

## License
MIT License

Copyright (c) 2026

Permission is hereby granted, free of charge, to any person obtaining a copy
of this software and associated documentation files (the "Software"), to deal
in the Software without restriction, including without limitation the rights
to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
copies of the Software, and to permit persons to whom the Software is
furnished to do so, subject to the following conditions:

The above copyright notice and this permission notice shall be included in all
copies or substantial portions of the Software.

THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE
SOFTWARE.
