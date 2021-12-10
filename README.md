# Spring Boot Authentication SAML 2.0 with Keycloak and Okta

### Tasks
    [X] Libs configuration
    [X] Keycloak configuration for new application
    [X] SAML connection for kecloak
    [X] Okta configuration for new application
    [X] Tests with new profile 

## SAML 2.0 Integration - Federation

### **Creating keys**
1. Create keystore

	keytool -genkeypair -alias demosaml2 -keypass saml123456 -keystore saml-keystore.jks -keyalg RSA -keysize 2048

2. Export cert and import into IDP (Identity Provider)

	keytool -export -keystore saml-keystore.jks -alias demosaml2 -file saml2.cer

3. Add form cert into IDP (** not tested yet **)

	keytool -importcert -alias myidp -file saml2.cer -keystore saml-keystore.jks
	
## Configure Okta SLO
1. On the **Configure SAML** page, click **Show Advanced Settings***.
2. Select the check box to **Allow application to initiate Single Logout**.
3. Configure properties:
    1. Single Logout url: http://localhost:8080/spring-security-saml2-sample/saml/logout
    2. SP Issuer : http://localhost:8080/spring-security-saml2-sample/saml/metadata
    3. Created certificate (saml2.cer) and uploaded.
