# Spring Boot Authentication SAML 2.0 with Keycloak and Okta

### Tasks
    [X] Libs configuration
    [X] Keycloak configuration for new application
    [X] SAML connection for kecloak
    [ ] Okta configuration for new application
    [ ] Tests with new profile 

# SAML 2.0 Integration - Federation

** 1. Creating keys **

1.1. Create keystore

	keytool -genkeypair -alias demosaml2 -keypass saml123456 -keystore saml-keystore.jks -keyalg RSA -keysize 2048

1.2. Export cert and import into IDP (Identity Provider)

	keytool -export -keystore saml-keystore.jks -alias demosaml2 -file saml2.cer

	