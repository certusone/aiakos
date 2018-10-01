aiakos
==

Aiakos is a [Tendermint](https://github.com/tendermint/tendermint) PrivValidator (signer) implementation using the YubiHSM2.

It uses the [yubihsm-go](https://github.com/certusone/yubihsm-go) library to communicate with the YubiHSM connector which needs to be running on the HSM host.

## Usage

To implement the PV interface in your Tendermint application you need to initialize it appropriately. To simplify the state management we implemented Tendermint's Service system.

The following example shows you how to implement a simple Aiakos service using env variables (please note that some errors are unhandled for simplicity).
We are using the tendermint `log` package for the service initialization and further log output.

```
if os.Getenv("AIAKOS_URL") == "" {
  return nil, errors.New("no Aiakos hsm url specified. Please set AIAKOS_URL in the format host:port")
}
aiakosUrl := os.Getenv("AIAKOS_URL")

if os.Getenv("AIAKOS_SIGNING_KEY") == "" {
  return nil, errors.New("no Aiakos signing key ID specified. Please set AIAKOS_SIGNING_KEY")
}
aiakosSigningKey, err := strconv.ParseUint(os.Getenv("AIAKOS_SIGNING_KEY"), 10, 16)
if err != nil {
  return nil, errors.New("invalid Aiakos signing key ID.")
}

if os.Getenv("AIAKOS_AUTH_KEY") == "" {

  return nil, errors.New("no Aiakos auth key ID specified. Please set AIAKOS_AUTH_KEY")
}
aiakosAuthKey, err := strconv.ParseUint(os.Getenv("AIAKOS_AUTH_KEY"), 10, 16)
if err != nil {
  return nil, errors.New("invalid Aiakos auth key ID.")
}

if os.Getenv("AIAKOS_AUTH_KEY_PASSWORD") == "" {
  return nil, errors.New("no Aiakos auth key password specified. Please set AIAKOS_AUTH_KEY_PASSWORD")
}
aiakosAuthPassword := os.Getenv("AIAKOS_AUTH_KEY_PASSWORD")

// Init Aiakos module
hsm, err := aiakos.NewAiakosPV(aiakosUrl, uint16(aiakosSigningKey), uint16(aiakosAuthKey), aiakosAuthPassword, log.NewNopLogger())
if err != nil {
  return nil, err
}

// Start Aiakos
err = hsm.Start()
if err != nil {
  return nil, err
}

if os.Getenv("AIAKOS_IMPORT_KEY") == "TRUE" {
  println("importing private key to Aiakos because AIAKOS_IMPORT_KEY is set.")

  filepv := privval.LoadOrGenFilePV("privval.json")
  key := filepv.PrivKey.(ed25519.PrivKeyEd25519)

  err = hsm.ImportKey(uint16(aiakosSigningKey), key[:32])
  if err != nil {
    println("Could not import key to HSM; skipping this step since it probably already exists")
  }
}

```

Now you can use `hsm` as the PV in your Tendermint App initializer.

## Notice

This has only been tested with Tendermint `v0.24.x`