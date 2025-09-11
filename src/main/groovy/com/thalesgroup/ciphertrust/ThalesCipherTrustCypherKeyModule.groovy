package com.thalesgroup.ciphertrust

import com.morpheusdata.core.providers.CypherModuleProvider
import com.morpheusdata.core.MorpheusContext
import com.morpheusdata.core.Plugin
import com.morpheusdata.core.util.HttpApiClient
import com.morpheusdata.model.AccountCredential
import com.morpheusdata.model.AccountIntegration
import com.morpheusdata.cypher.Cypher;
import com.morpheusdata.cypher.CypherMeta;
import com.morpheusdata.cypher.CypherModule;
import com.morpheusdata.cypher.CypherObject

import com.morpheusdata.model.OptionType
import com.morpheusdata.response.ServiceResponse
import groovy.json.JsonSlurper
import groovy.json.JsonOutput
import groovy.util.logging.Slf4j



@Slf4j
class ThalesCipherTrustCypherKeyModule implements CypherModule {

    static List<String> SUPPORTED_ALGORITHMS = ['aes', 'tdes', 'rsa', 'ec', 'hmac-sha1', 'hmac-sha256', 'hmac-sha384', 'hmac-sha512', 'seed', 'aria', 'opaque']

    Cypher cypher
    ThalesCipherTrustPlugin plugin
    String jwtToken
    long timeJWT
    ThalesCipherTrustCypherKeyProvider provider

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

    public void setProvider(ThalesCipherTrustCypherKeyProvider provider) {
        this.provider = provider
    }


    @Override
    public CypherObject write(String relativeKey, String path, String value, Long leaseTimeout, String leaseObjectRef, String createdBy) {
            log.info("CypherObject write.....")
        log.info("PATH IS: $path")
        log.info("KEY IS: $relativeKey")

        HttpApiClient apiClient = new HttpApiClient()

        apiClient.networkProxy = morpheusContext.services.setting.getGlobalNetworkProxy()
        String apiUrl = plugin.getUrl();
        String username = plugin.getServiceUsername();
        String password = plugin.getServicePassword();
        String domain = plugin.getDomain();

        try {
            def authResults = authToken(apiUrl,username,password,domain)
            def body = ['description': "$path/$relativeKey"]
            if(authResults.success) {
                String bearerString = 'Bearer ' + jwtToken
                String endpoint = 'v1/vault/keys2'
                def splitKey = relativeKey.split("/")

                if (relativeKey.startsWith "rotate/") {
                    log.debug("key rotation requested ${relativeKey}")
                    def urlKey = (splitKey.length > 1) ? splitKey[1] : splitKey[0]
                    endpoint += "/$urlKey/versions"
                } else {
                    if (splitKey.length > 1) {
                        if (!SUPPORTED_ALGORITHMS.contains(splitKey[0])) throw new Exception("Algorithm '${splitKey[0]} not supported.'")
                        body['algorithm'] = splitKey[0]
                    } else {
                        log.error("Algorithm not supplied. Please provide mount point in the form ${this.provider.getCypherMountPoint()}/aes/mykeyname ")
                        body['algorithm'] = SUPPORTED_ALGORITHMS[0] //aes
                        relativeKey = "${SUPPORTED_ALGORITHMS[0]}/$relativeKey"
                    }
                    body['name'] = splitKey[-1]
                }
                def headers = ['Accept': 'application/json', 'Content-Type': 'application/json', 'Authorization': bearerString ]
                HttpApiClient.RequestOptions restOptions = new HttpApiClient.RequestOptions([headers: headers , body: body])
                def apiResults = apiClient.callApi(apiUrl, endpoint, null, null, restOptions, 'POST')
                log.info("apiResults: ${apiResults.toMap()}")
                log.info("Path/Key: $path/$relativeKey")
                if(apiResults.success) {
                    CypherObject rtn = new CypherObject("$path/$relativeKey", value, leaseTimeout, leaseObjectRef, createdBy)
                    //rtn.shouldPersist = false;
                    return rtn
                } else {
                    log.error("Cypher failed to write key: ${apiResults.toMap()} ")
                    return null
                }
            } else {
                log.error("Cypher failed to authenticate to write key: ${authResults.toMap()} ")
                return null
            }
        } catch (Exception exception) {
            log.error("Exception: Cypher failed to write key", exception)
            return null
        }
        finally {
            apiClient.shutdownClient()
        }
    }


    @Override
    public CypherObject read(String key, String path, Long leaseTimeout, String leaseObjectRef, String createdBy) {

        HttpApiClient apiClient = new HttpApiClient()

        apiClient.networkProxy = morpheusContext.services.setting.getGlobalNetworkProxy()
        String apiUrl = plugin.getUrl();
        String username = plugin.getServiceUsername();
        String password = plugin.getServicePassword();
        String domain = plugin.getDomain();

        try {
            def authResults = authToken(apiUrl, username, password, domain)

            if (authResults.success) {
                String bearerString =    'Bearer ' + jwtToken
                def headers = ['Accept': 'application/json', 'Content-Type': 'application/json' , 'Authorization': bearerString ]
                //def body = ['type': 'name']

                HttpApiClient.RequestOptions restOptions = new HttpApiClient.RequestOptions([headers: headers])
                /*log.info("header is  ${headers}")
                log.info("body is  ${body}")
                log.info("key is ${key}")
                log.info("path is  ${path}")
                 */
                String endPoint = 'v1/vault/keys2/' + key.split('/')[-1] + '/export'
                //log.info("endPoint is ${endPoint}")

                def apiResults = apiClient.callApi(apiUrl,endPoint,null,null,restOptions,'POST')

                if(apiResults.getSuccess()) {
                    def jsonSlurper = new JsonSlurper()
                    def resultContent = jsonSlurper.parseText (apiResults.content.toString())

                    log.debug("Successfully retrieved key ${key}")
                    //log.info("Successfully retrieved key material ${resultContent.material}")

                    CypherObject keyResults = new CypherObject("$path/$key", resultContent.material, leaseTimeout, leaseObjectRef, createdBy)
                    keyResults.shouldPersist = false;
                    return keyResults;
                } else {
                    log.debug("Cypher failed to read key ")
                    return new CypherObject("$path/$key", "Error Retrieving Secret", leaseTimeout, leaseObjectRef, createdBy)
                }
            } else {
                log.error("Cypher failed to read key ")
                return new CypherObject("$path/$key", "Error Retrieving Secret", leaseTimeout, leaseObjectRef, createdBy)
            }
        } catch (Exception exception) {
            log.error("Cypher failed to read key ", exception)
            return new CypherObject("$path/$key", "Error Retrieving Secret",leaseTimeout,leaseObjectRef, createdBy)
        }
        finally {
            apiClient.shutdownClient()
        }
    }


    @Override
    public boolean delete(String key, String path, CypherObject object) {
        log.info("Key to delete: $key")

        HttpApiClient apiClient = new HttpApiClient()

        apiClient.networkProxy = morpheusContext.services.setting.getGlobalNetworkProxy()
        String apiUrl = plugin.getUrl();
        String username = plugin.getServiceUsername();
        String password = plugin.getServicePassword();
        String domain = plugin.getDomain();

        try {
            def authResults = authToken(apiUrl, username, password, domain)

            if (authResults.success) {
                String bearerString = 'Bearer ' + jwtToken

                def headers = ['Accept': 'application/json', 'Content-Type': 'application/json', 'Authorization': bearerString]

                HttpApiClient.RequestOptions restOptions = new HttpApiClient.RequestOptions([headers: headers])
                String endPoint = 'v1/vault/keys2/' + key.split("/")[-1]

                def apiResults = apiClient.callApi(apiUrl, endPoint, null, null, restOptions, 'DELETE')
                if (apiResults.getSuccess()) {
                    log.debug("Successfully deleted key ${key} ")
                    return true
                } else {
                    log.error("Cypher failed to delete key ")
                    return false
                }
            } else {
                log.error("Cypher failed to delete key  ")
                return false
            }
        } catch (Exception exception) {
            log.error("Cypher failed to delete key", exception)
            return false
        }
        finally {
            apiClient.shutdownClient()
        }
    }

    protected ServiceResponse<Map> authToken(String apiUrl, String username, String password, String domain) {
        long currentTime = System.currentTimeMillis() / 1000

        //give a cushion of 10 seconds
        if(this.timeJWT > (currentTime + 10)) {
            return  ServiceResponse.success("Credentials auth token still valid")
        }

        HttpApiClient apiClient = new HttpApiClient()
        apiClient.networkProxy = morpheusContext.services.setting.getGlobalNetworkProxy()\

        def headers = ['Accept': 'application/json' , 'Content-Type':'application/json']
        def body = ['grant_type':'password' , 'domain':domain , 'username':username , 'password':password ]

        HttpApiClient.RequestOptions restOptions = new HttpApiClient.RequestOptions([headers:headers , body:body])


        try {
            def apiResults = apiClient.callApi(apiUrl,'v1/auth/tokens',null,null,restOptions,'POST')

            if(apiResults.success) {
                def jsonSlurper = new JsonSlurper()
                def resultContent = jsonSlurper.parseText (apiResults.content.toString())

                this.jwtToken = resultContent.jwt
                //default expire in 300 seconds
                this.timeJWT = (System.currentTimeMillis() / 1000) + 300

                return  ServiceResponse.success("Successfully retrieve cypher token from authToken")

            } else {
                log.error("Failed to retrieve a new cypher token ")
                return ServiceResponse.error(apiResults.error ?: apiResults.content ?: "An unknown error occurred authenticating CipherTrust")
            }
        } catch (Exception exception) {
            log.error("authToken cypher ", exception)
            return ServiceResponse.error("An unknown error occurred authenticating CipherTrust")
        }
        finally {
            apiClient.shutdownClient()
        }

    }


    @Override
    public String getUsage() {
        return "This allows cyphers to use Thales CipherTrust Manager Keys. This can be configured in the plugin integration settings. Provide 'generate' as the value below."
    }

    @Override
    public String getHTMLUsage() {
        return null;
    }


    @Override
    Boolean readFromDatastore() {
        return false //important to ensure reads are always obtained from ciphertrust
    }
}
