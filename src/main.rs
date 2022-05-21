//! cargo run --example account_create

use std::path::PathBuf;

use identity::account::Account;
use identity::account::AccountBuilder;
use identity::account::AccountStorage;
use identity::account::AutoSave;
use identity::account::IdentitySetup;
use identity::account::Result;
use identity::core::json;
use identity::core::FromJson;
use identity::core::ToJson;
use identity::core::Url;
use identity::credential;
use identity::credential::Credential;
use identity::credential::Presentation;
use identity::credential::PresentationBuilder;
use identity::credential::Subject;
use identity::crypto::SignatureOptions;
use identity::did::verifiable::VerifierOptions;
use identity::did::DID;
use identity::iota::ClientBuilder;
use identity::iota::ClientMap;
use identity::iota::CredentialValidation;
use identity::iota::CredentialValidator;
use identity::iota::ExplorerUrl;
use identity::iota::IotaDID;
use identity::iota::Network;
use identity::iota::PresentationValidation;
use identity::iota::ResolvedIotaDocument;
use identity::prelude::KeyPair;

async fn create_did(account_builder: &mut AccountBuilder) -> Result<IotaDID> {
    // Create a new identity using Stronghold as local storage.
    //
    // The creation step generates a keypair, builds an identity
    // and publishes it to the IOTA mainnet.
    let account: Account = account_builder
        .create_identity(IdentitySetup::default())
        .await?;

    // Retrieve the did of the newly created identity.
    let iota_did: &IotaDID = account.did();

    // Print the local state of the DID Document
    println!(
        "[Example] Local Document from {} = {:#?}",
        iota_did,
        account.document()
    );

    Ok(iota_did.clone())
}

// add more methods like these add, delete, and combine them
// more example from account/manipulate_did.rs
async fn update_did_add_key_method(
    account_builder: &mut AccountBuilder,
    iota_did: IotaDID,
    key_fragment_specifier: &str,
) -> Result<IotaDID> {
    // We can load the identity from storage into an account using the builder.
    let mut account: Account = account_builder.load_identity(iota_did).await?;

    // Add another Ed25519 verification method to the identity
    account
        .update_identity()
        .create_method()
        .fragment(key_fragment_specifier)
        .apply()
        .await?;

    // Retrieve the did of the newly created identity.
    let iota_did: &IotaDID = account.did();

    // Print the local state of the DID Document
    println!(
        "[Example] Local Document from {} = {:#?}",
        iota_did,
        account.document()
    );

    Ok(iota_did.clone())
}

// how to enforce schema of credential,
// credential type should be an input param and enum
async fn build_unsigned_credential(issuer_did: IotaDID, subject: Subject) -> Result<Credential> {
    // Issue an unsigned Credential...
    Ok(Credential::builder(Default::default())
        .issuer(Url::parse(issuer_did.as_str())?)
        .type_("UniversityDegreeCredential")
        .subject(subject)
        .build()?)
}

// can we deduce key_fragment_specifier from did_url
// how to enforce schema of crdential,
// credential type should be an input param and enum
async fn sign_credential(
    account_builder: &mut AccountBuilder,
    issuer_did: IotaDID,
    key_fragment_specifier: &str,
    credential: &mut Credential,
) -> Result<()> {
    // We can load the identity from storage into an account using the builder.
    let account: Account = account_builder.load_identity(issuer_did).await?;

    // ...and sign the Credential with the previously created Verification Method
    account
        .sign(
            key_fragment_specifier,
            credential,
            SignatureOptions::default(),
        )
        .await?;

    // Fetch the DID Document from the Tangle
    //
    // This is an optional step to ensure DID Document consistency.
    let resolved: ResolvedIotaDocument = account.resolve_identity().await?;

    // Retrieve the DID from the newly created identity.
    let iota_did: &IotaDID = account.did();

    // Prints the Identity Resolver Explorer URL.
    // The entire history can be observed on this page by clicking "Loading History".
    let explorer: &ExplorerUrl = ExplorerUrl::mainnet();
    println!(
        "[Example] Explore the DID Document = {}",
        explorer.resolver_url(iota_did)?
    );

    // Ensure the resolved DID Document can verify the credential signature
    let verified: bool = resolved
        .document
        .verify_data(&credential, &VerifierOptions::default())
        .is_ok();

    println!("[Example] Credential Verified = {}", verified);

    Ok(())
}

/// Convenience function for checking that a verifiable credential is valid and not revoked.
pub async fn validate_credential(
    client: &ClientMap,
    credential: &Credential,
) -> Result<CredentialValidation> {
    // Convert the Verifiable Credential to JSON to potentially "exchange" with a verifier
    let credential_json = credential.to_json()?;

    // Create a `CredentialValidator` instance to fetch and validate all
    // associated DID Documents from the Tangle.
    let validator: CredentialValidator<ClientMap> = CredentialValidator::new(client);

    // Perform the validation operation.
    let validation: CredentialValidation = validator
        .check_credential(&credential_json, VerifierOptions::default())
        .await?;
    Ok(validation)
}

// TODO challenge format
// TODO check on presentation format, security issues, what issuer is siging, need to validate check
// credential type should be an input param and enum
async fn sign_presentation(
    account_builder: &mut AccountBuilder,
    issuer_did: IotaDID,
    key_fragment_specifier: &str,
    presentation: &mut Presentation,
    challenge: &str,
) -> Result<()> {
    // We can load the identity from storage into an account using the builder.
    let account: Account = account_builder.load_identity(issuer_did).await?;

    // sign the Presentation
    account
        .sign(
            key_fragment_specifier,
            presentation,
            SignatureOptions::new().challenge(challenge.to_owned()),
        )
        .await?;

    // Fetch the DID Document from the Tangle
    //
    // This is an optional step to ensure DID Document consistency.
    let resolved: ResolvedIotaDocument = account.resolve_identity().await?;

    // Retrieve the DID from the newly created identity.
    let iota_did: &IotaDID = account.did();

    // Prints the Identity Resolver Explorer URL.
    // The entire history can be observed on this page by clicking "Loading History".
    let explorer: &ExplorerUrl = ExplorerUrl::mainnet();
    println!(
        "[Example] Explore the DID Document = {}",
        explorer.resolver_url(iota_did)?
    );

    // Ensure the resolved DID Document can verify the credential signature
    let verified: bool = resolved
        .document
        .verify_data(&presentation, &VerifierOptions::default())
        .is_ok();

    println!("[Example] Credential Verified = {}", verified);

    Ok(())
}

// TODO challenge format
/// Convenience function for checking that a verifiable presentation is valid and not revoked.
pub async fn validate_presentation(
    client: &ClientMap,
    presentation: &Presentation,
    challenge: &str,
) -> Result<PresentationValidation> {
    // Convert the Verifiable Presentation to JSON and "exchange" with a verifier
    let presentation_json: String = presentation.to_json()?;

    // Create a `CredentialValidator` instance to fetch and validate all
    // associated DID Documents from the Tangle.
    let validator: CredentialValidator<ClientMap> = CredentialValidator::new(client);

    // Validate the presentation and all the credentials included in it.
    //
    // Also verify the challenge matches.
    let validation: PresentationValidation = validator
        .check_presentation(
            &presentation_json,
            VerifierOptions::new().challenge(challenge.to_owned()),
        )
        .await?;
    println!("validation = {:#?}", validation);

    Ok(validation)
}

#[tokio::main]
async fn main() -> Result<()> {
    pretty_env_logger::init();

    // Set-up for a private Tangle
    // You can use https://github.com/iotaledger/one-click-tangle for a local setup.
    // The `network_name` needs to match the id of the network or a part of it.
    // As an example we are treating the devnet as a private tangle, so we use `dev`.
    // When running the local setup, we can use `tangle` since the id of the one-click
    // private tangle is `private-tangle`, but we can only use 6 characters.
    // Keep in mind, there are easier ways to change to devnet via `Network::Devnet`
    let network_name = "dev";
    let network = Network::try_from_name(network_name)?;

    // If you deployed an explorer locally this would usually be `http://127.0.0.1:8082`
    let explorer = ExplorerUrl::parse("https://explorer.iota.org/devnet")?;

    // In a locally running one-click tangle, this would usually be `http://127.0.0.1:14265`
    let private_node_url = "https://api.lb-0.h.chrysalis-devnet.iota.cafe";

    // Sets the location and password for the Stronghold
    //
    // Stronghold is an encrypted file that manages private keys.
    // It implements best practices for security and is the recommended way of handling private keys.
    let stronghold_path: PathBuf = "./example-strong.hodl".into();
    let password: String = "my-password".into();

    /*     let mut account_builder: AccountBuilder = Account::builder().storage(
        AccountStorage::Stronghold(stronghold_path, Some(password), None),
    ); */

    // Create a new Account with explicit configuration
    let mut account_builder: AccountBuilder = Account::builder()
        //.autosave(AutoSave::Never) // never auto-save. rely on the drop save
        .autosave(AutoSave::Every) // save immediately after every action
        //.autosave(AutoSave::Batch(10)) // save after every 10 actions
        .autopublish(true) // publish to the tangle automatically on every update
        .milestone(1) // save a snapshot every 4 actions
        .storage(AccountStorage::Stronghold(
            stronghold_path,
            Some(password),
            None,
        ))
        .client_builder(
            // Configure a client for the private network
            ClientBuilder::new().network(network.clone()).primary_node(
                private_node_url,
                None,
                None,
            )?, // .permanode(<permanode_url>, None, None)? // set a permanode for the same network
        );

    let iota_did = create_did(&mut account_builder).await?;

    // Prints the Identity Resolver Explorer URL.
    // The entire history can be observed on this page by clicking "Loading History".
    // let explorer: &ExplorerUrl = ExplorerUrl::mainnet();
    println!(
        "[Example] Explore the DID Document = {}",
        explorer.resolver_url(&iota_did)?
    );

    // ===========================================================================
    // Signing Example
    // ===========================================================================

    let key_fragment_specifier = "my-key";
    // Optional - Add a new Ed25519 Verification Method to the identity
    let iota_did_new = update_did_add_key_method(
        &mut account_builder,
        iota_did.clone(),
        key_fragment_specifier,
    )
    .await?;

    // Print the local state of the DID Document
    println!("[Example] Local Document from {} ", iota_did_new,);

    // Create a subject DID for the recipient of a `UniversityDegree` credential.
    let subject_key: KeyPair = KeyPair::new_ed25519()?;
    let subject_did: IotaDID = IotaDID::new(subject_key.public().as_ref())?;

    // Create the actual Verifiable Credential subject.
    let subject: Subject = Subject::from_json_value(json!({
      "id": subject_did.as_str(),
      "degree": {
        "type": "BachelorDegree",
        "name": "Bachelor of Science and Arts"
      }
    }))?;

    // First build an unsigned credential
    let mut credential: Credential = build_unsigned_credential(iota_did.clone(), subject).await?;

    // Then issue a signed Credential...
    sign_credential(
        &mut account_builder,
        iota_did.clone(),
        key_fragment_specifier,
        &mut credential,
    )
    .await?;

    println!("Credential JSON > {:#}", credential);

    // Create a client instance to send messages to the Tangle.
    let client: ClientMap = ClientMap::new();

    // Validate the verifiable credential
    let validation: CredentialValidation = validate_credential(&client, &credential).await?;
    println!("Credential Validation > {:#?}", validation);
    assert!(validation.verified);

    let challenge = "475a7984-1bb5-4c4c-a56f-822bccd46440";

    // Create an unsigned Presentation from the previously issued Verifiable Credential.
    let mut presentation: Presentation = PresentationBuilder::default()
        .id(Url::parse("asdf:foo:a87w3guasbdfuasbdfs")?)
        .holder(Url::parse(subject_did.as_ref())?)
        .credential(credential)
        .build()?;

    // Then issue a signed the Verifiable Presentation...
    sign_presentation(
        &mut account_builder,
        iota_did.clone(),
        key_fragment_specifier,
        &mut presentation,
        challenge,
    )
    .await?;

    // Validate the verifiable presentation
    let validation: PresentationValidation =
        validate_presentation(&client, &presentation, challenge).await?;
    println!("Presentation Validation > {:#?}", validation);
    assert!(validation.verified);
    Ok(())
}
