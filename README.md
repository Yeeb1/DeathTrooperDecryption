# DeathTrooperDecryption

<p align="center">
  <img src="/img/DT_Encryption_Empire_Ascendant.webp" width="400">
</p>

> *Death trooper encryption was a language used by the Galactic Empire's elite death troopers. The troopers spoke the language using voice-scramblers built into their helmets, allowing them to communicate with each other without anyone being able to decipher what they were saying, as well as enhance their intimidating image.*  
>  
> — [Wookieepedia - Death trooper encryption](https://starwars.fandom.com/wiki/Death_trooper_encryption)

## Description

The **DeathTrooperDecryption** toolkit is a specialized suite of helper tools designed to facilitate the analysis and understanding of agent communication within the [**Empire C2 framework**](https://github.com/BC-SECURITY/Empire). The suite provides capabilities to decrypt and inspect various phases of communication between the Empire C2 server and its agents, including:

- **Staging Phase**: During the initial connection setup, the agent attempts to establish communication with the C2 server. The toolkit enables the decryption of key exchanges that occur during this phase, which are essential for securing subsequent communications.
- **Command Execution Phase**: Once the agent is staged, the Empire server can issue commands and receive responses, as well as execute post-exploitation modules. The tools here decrypt traffic for both these tasks and any returned results, enabling an in-depth view of communication patterns.

### Communication Phases

The Empire C2 communication consists of two main phases:

1. **Staging Phase**:
   - In this initial phase, the agent tries to set up a secure connection to the Empire C2 server. Multiple key exchanges occur here, setting up encryption keys for subsequent communications.
   - The DeathTrooperDecryption suite allows users to decrypt Empire’s staged payloads in multiple steps, including RC4, RSA, and AES decryption with HMAC verification, as used by Empire.

2. **Command/Post-Exploitation Phase**:
   - After staging, the agent communicates regularly with the server to either send updates (like command outputs) or receive tasks.
   - The suite also decrypts data from various modules that may run extended jobs or collect data like clipboard contents and system info.

### Supported Decryption Methods

To fully decode the encrypted data exchanged between the agent and server, **DeathTrooperDecryption** uses a combination of cryptographic techniques:

- **RC4**: Decrypts initial staged payloads from Empire, using the staging key to decipher cookies and identify the communication stage.
- **RSA**: Decodes initial payloads encrypted with asymmetric keys during the staging phase, establishing secure initial communication.
- **AES with HMAC**: Decrypts payloads exchanged after the staging phase, verifying each with an HMAC for message integrity.

## Stage 0: Initial Staging Script Decryption

In the **Stage 0** phase of Empire's staging process, the C2 server sends an encrypted staging script to the agent as part of its initial communication. Decrypting this script requires the *staging key*, a critical component already used during the initial execution of the stager on the compromised host. This key enables decryption of the server's response, providing access to the staging script necessary for further communication setup.

The **Stage 0 Decryption Script** (`stage0_decrypt_stager.py`) in this toolkit is designed to:
1. Accept the *staging key* as input, which will be used for RC4 decryption.
2. Use this key to decrypt the server’s Stage 0 response payload, revealing the initial script sent to the agent.

### Usage

To decrypt the Stage 0 response, ensure you have the staging key and the file containing the hex-encoded datastream retrieved from the C2 server. The tool accepts the following options:

```bash
┌──(kalikali)-[~/DeathTrooperDecryption]
└─$ python3 stage0_decrypt_stager.py -k 'o#(dJEG>T^clWBb@Z.kP31)5~AvMIgjr' -f stage0_serverresponse.hex --output decrypted_payload.ps1 -h
usage: stage0.py [-h] --key KEY --file FILE [--output OUTPUT] [--verbose]

Empire C2 Stager Decryption Script

options:
  -h, --help            show this help message and exit
  --key KEY, -k KEY     Session key used for RC4 decryption
  --file FILE, -f FILE  Path to the file containing the hex data stream
  --output OUTPUT, -o OUTPUT
                        Output filename to save the decrypted payload (default: decrypted_payload.txt)
  --verbose, -v         Enable verbose output for debugging

Example usage: python stage0_decrypt_stager.py --key "StagingKey" --file "hex_data.txt" --output "decrypted_payload.ps1"
```

#### Technical Details

The script decrypts the payload using the following steps:

1. **RC4 Key Derivation**: The RC4 key used for decryption combines:
   - The first 4 bytes of the encrypted data (`enc_data[:4]`), known as the RC4 IV.
   - The staging key (or session key), specified by the user.

   These two components are concatenated to form the final RC4 key: `rc4_key = rc4_iv + session_key`.

2. **RC4 Decryption**: The script uses this RC4 key to decrypt the remainder of the data (from the 5th byte onward), revealing the server's staging script.

3. **Output**: The decrypted payload is saved to a specified output file, which can be a PowerShell script containing the commands the agent needs to initialize further communications.

4. **Display of Decrypted Payload**: The script attempts to decode the decrypted data as UTF-8 text and prints it for easy inspection.


### Stage 1: Key Exchange Decryption

In **Stage 1** of Empire's staging process, the agent establishes a secure channel with the C2 server by generating an RSA key pair. The public key from this pair is sent to the server, allowing for secure key exchange. Recovering the RSA public key from this exchange is essential for monitoring or analyzing the session’s encryption, and the modulus extracted from this key can be used with [CovenantDecryptor](https://github.com/naacbin/CovenantDecryptor) to recover the private key from the agent’s process, either via a live capture or memory dump.

The **Stage 1 Key Exchange Decryption Script** (`stage1_keyexchange.py`) enables users to:
1. Retrieve the agent's RSA public key from the Empire C2 server's response.
2. Extract the modulus of the RSA key, which can then be used with CovenantDecryptor to recover the private key.

#### Usage

To run the script, provide the *staging key* for RC4 and AES decryption along with the file containing the hex-encoded data stream from the server’s response. Here’s the command structure:

```bash
python3 stage1_keyexchange.py --key 'o#(dJEG>T^clWBb@Z.kP31)5~AvMIgjr' --file path/to/hex_data.txt --output decrypted_RSA.xml -h
usage: stage1_keyexchange.py [-h] --key KEY --file FILE [--output OUTPUT] [--verbose]

Empire C2 Stage1 Key Exchange Decryption Script

options:
  -h, --help            show this help message and exit
  --key KEY, -k KEY     Staging key used for RC4 and AES decryption
  --file FILE, -f FILE  Path to the file containing the hex data stream
  --output OUTPUT, -o OUTPUT
                        Output filename to save the decrypted payload (default: decrypted_RSA.xml)
  --verbose, -v         Enable verbose output for debugging

Example usage: python stage1_keyexchange.py --key "StagingKey" --file "hex_data.txt"
```

#### Technical Details

The Stage 1 decryption process involves the following steps:

1. **RC4 Key Derivation and Decryption**:
   - The first 4 bytes of the encrypted data (`enc_data[:4]`) act as the RC4 IV. These are combined with the provided *staging key* to form the RC4 key: `rc4_key = rc4_iv + staging_key`.
   - This RC4 key is then used to decrypt the next 16 bytes of the payload (`enc_data[4:20]`). The decrypted result contains session information needed for further communication setup.

2. **Interpretation of Packet Structure**:
   - The script interprets and logs key session information extracted from the decrypted payload, including:
     - **Session ID**: Identifies the current session.
     - **Language**: Specifies the language used by the agent (e.g., PowerShell, Python).
     - **Meta Field**: Indicates the type of communication (e.g., Tasking Request, Server Response).
     - **Data Length**: The length of the AES-encrypted data that follows.

3. **AES Decryption**:
   - The next section of `enc_data` (following the session information) contains the AES-encrypted payload.
   - The AES key used for this decryption is the *staging key*, and the IV is derived from the AES-encrypted data itself.
   - **HMAC Verification**: The last 10 bytes of this section contain an HMAC signature, used to verify the integrity of the ciphertext. If the HMAC check passes, the payload is decrypted using AES in CBC mode and unpadded to reveal the full decrypted content.

4. **Extraction of RSA Public Key**:
   - The decrypted payload typically contains an XML-formatted RSA public key (used by the agent for further encryption with the Empire C2 server).
   - The script extracts and prints this RSA key, saving it to the specified output file.
   - Additionally, the modulus of the RSA key is extracted and displayed, which can be used with tools like [https://github.com/naacbin/CovenantDecryptor](https://github.com/naacbin/CovenantDecryptor) for private key recovery from a live process or memory dump.



### Stage 2: Decryption of Agent Data Sent to the C2 Server

In **Stage 2**, the decrypted data contains critical information, as it includes encrypted command output and other agent response data sent back to the C2 server. To decrypt this data, the private RSA key generated by the agent during Stage 1 is required. This stage is essential for extracting the agent's output for executed tasks and other command results sent to the C2 server.

The **Stage 2 Decryption Script** (`stage2_decrypt_agentdata.py`) allows users to:
1. Decrypt the command output data from the agent using the private RSA key and staging key.
2. Base64-decode and parse the extracted agent response data, making it available for analysis.

#### Usage

To run the script, provide the *private RSA key* and the *staging key* used in the earlier stages, along with the relevant hex-encoded data files from the server and agent. Here’s the command structure:

```bash
python3 stage2_decrypt_agentdata.py --privkey path/to/private_key.pem --stage1_response path/to/stage1_response.bin --stage2_request path/to/stage2_request.bin --staging_key "o#(dJEG>T^clWBb@Z.kP31)5~AvMIgjr" --output decoded_payload.txt -h

usage: stage2_decrypt_agentdata.py [-h] --privkey PRIVKEY --stage1_response STAGE1_RESPONSE --stage2_request STAGE2_REQUEST --staging_key STAGING_KEY
                                   [--output OUTPUT] [--verbose]

Decrypt agent data sent to the C2 server

options:
  -h, --help            show this help message and exit
  --privkey PRIVKEY, -p PRIVKEY
                        Path to the private RSA key file (PEM format)
  --stage1_response STAGE1_RESPONSE, -s1 STAGE1_RESPONSE
                        Path to the stage1 RSA-encrypted response file (hex encoded)
  --stage2_request STAGE2_REQUEST, -s2 STAGE2_REQUEST
                        Path to the stage2 request file (hex encoded)
  --staging_key STAGING_KEY, -k STAGING_KEY
                        Staging key used for RC4 decryption
  --output OUTPUT, -o OUTPUT
                        Output filename to save the decoded payload (default: decoded_payload.txt)
  --verbose, -v         Enable verbose output for debugging

Example usage: python stage2_decrypt_agentdata.py --privkey <private_key> --stage1_response <file> --stage2_request <file> --staging_key <key>
```

#### Technical Details

The Stage 2 decryption process involves the following steps:

1. **Loading the Private RSA Key**: 
   - The RSA private key (generated by the agent in memory during Stage 1) is required to decrypt the nonce and session key used in the agent's communication.

2. **Deriving Session Key from Stage 1 Response**:
   - The script decrypts the Stage 1 RSA-encrypted response using the private key to retrieve the session key and nonce required for AES decryption of agent data in Stage 2.

3. **RC4 Decryption of Session Information**:
   - Similar to previous stages, the script uses RC4 decryption on the initial 16-byte session information from the encrypted payload. The RC4 key is constructed by combining the first 4 bytes of `enc_data` (the RC4 IV) with the staging key.

4. **Parsing Session Information**:
   - Key information about the session is extracted, such as:
     - **Session ID**
     - **Language** (e.g., PowerShell, Python)
     - **Meta Field** (e.g., Tasking Request, Result Post)
     - **Data Length** for AES decryption.

5. **AES Decryption with HMAC Verification**:
   - Using the session key obtained earlier, the AES-encrypted data (following the session information) is decrypted.
   - **HMAC Verification**: The last 10 bytes of the AES-encrypted section contain an HMAC signature to validate data integrity. The HMAC is verified against the expected value calculated using the session key.

6. **Processing Decrypted Payload**:
   - Once decrypted, the script removes the first 12 bytes from the payload, as these are not needed for output recovery.
   - The remaining payload is then base64-decoded, revealing the actual command output or module results sent from the agent to the C2 server.
   - The decoded payload is printed and saved to the specified output file.

This stage allows security analysts to view the full scope of agent interactions with the C2 server, including encrypted command output, making it a vital part of decrypting and analyzing Empire’s command-and-control communications.


