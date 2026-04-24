# envcrypt

A CLI tool for encrypting and managing `.env` files using [age](https://github.com/FiloSottile/age) encryption with team key sharing support.

---

## Installation

```bash
go install github.com/yourusername/envcrypt@latest
```

Or download a prebuilt binary from the [releases page](https://github.com/yourusername/envcrypt/releases).

---

## Usage

**Encrypt a `.env` file:**
```bash
envcrypt encrypt --file .env --output .env.age
```

**Decrypt a `.env` file:**
```bash
envcrypt decrypt --file .env.age --output .env
```

**Add a team member's public key:**
```bash
envcrypt keys add --alias alice --key age1ql3z7hjy54pw3hyww5ayyfg7zqgvc7w3j2elw8zmrj2kg5sfn9aqmcac8p
```

**Re-encrypt for all team keys:**
```bash
envcrypt reencrypt --file .env.age
```

---

## How It Works

`envcrypt` uses [age encryption](https://age-encryption.org/) under the hood. Each `.env` file is encrypted against one or more recipient public keys, allowing teams to share secrets securely without exposing plaintext credentials in version control.

Commit `.env.age` to your repository — never `.env`.

---

## Requirements

- Go 1.21+
- [age](https://github.com/FiloSottile/age) (bundled, no separate install needed)

---

## License

MIT © [yourusername](https://github.com/yourusername)