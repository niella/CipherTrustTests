package com.thalesgroup.ciphertrust

import com.morpheusdata.core.MorpheusContext
import com.morpheusdata.core.Plugin
import com.morpheusdata.cypher.Cypher
import com.morpheusdata.cypher.CypherModule
import com.morpheusdata.cypher.CypherObject

class ThalesCipherTrustCypherSecretModule implements CypherModule {

    Cypher cypher;
    ThalesCipherTrustPlugin plugin;
    String jwtToken;
    long timeJWT
    MorpheusContext morpheusContext

    @Override
    public void setCypher(Cypher cypher) {
        this.cypher = cypher;
    }

    public void setPlugin(ThalesCipherTrustPlugin plugin) {
        this.plugin = plugin
    }

    public void setMorpheusContext(MorpheusContext morpheusContext) {
        this.morpheusContext = morpheusContext
    }



    @Override
    CypherObject write(String relativeKey, String path, String value, Long leaseTimeout, String leaseObjectRef, String createdBy) {

        String apiUrl = plugin.getUrl();
        String username = plugin.getSecretsServiceUsername();
        String password = plugin.getSecretsServicePassword();
        String servicePath = plugin.getSecretsServicePath();

        return null
    }

    @Override
    CypherObject read(String relativeKey, String path, Long leaseTimeout, String leaseObjectRef, String createdBy) {

        String apiUrl = plugin.getUrl();
        String username = plugin.getSecretsServiceUsername();
        String password = plugin.getSecretsServicePassword();
        String servicePath = plugin.getSecretsServicePath();


        return null
    }

    @Override
    boolean delete(String relativeKey, String path, CypherObject object) {

        String apiUrl = plugin.getUrl();
        String username = plugin.getSecretsServiceUsername();
        String password = plugin.getSecretsServicePassword();
        String servicePath = plugin.getSecretsServicePath();

        return true
    }


    @Override
    String getUsage() {
        return "This allows cyphers to use Thales CipherTrust Manager Secrets. This can be configured in the plugin integration settings."
    }

    @Override
    String getHTMLUsage() {
        return null
    }

    @Override
    Boolean readFromDatastore() {
        return false
    }
}

