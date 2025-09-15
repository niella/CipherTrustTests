/*
* Copyright 2024 Jeff Ceason
*
* Licensed under the Apache License, Version 2.0 (the "License");
* you may not use this file except in compliance with the License.
* You may obtain a copy of the License at
*
*    http://www.apache.org/licenses/LICENSE-2.0
*
* Unless required by applicable law or agreed to in writing, software
* distributed under the License is distributed on an "AS IS" BASIS,
* WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
* See the License for the specific language governing permissions and
* limitations under the License.
*/
package com.thalesgroup.ciphertrust

import com.morpheusdata.core.Plugin
import com.morpheusdata.model.OptionType
import groovy.util.logging.Slf4j
import groovy.json.*
import com.morpheusdata.core.MorpheusContext

/**
 * @author Jeff Ceason
 */
@Slf4j
class ThalesCipherTrustPlugin extends Plugin {


	@Override
	String getCode() {
		return 'thales-ciphertrust-plugin'
	}

	@Override
	void initialize() {

		this.setName("Thales CipherTrust")
		this.setDescription("Thales CipherTrust Plugin")
		this.setAuthor("Thales")

		ThalesCipherTrustCredentialProvider cipherTrustCredentialProvider = new ThalesCipherTrustCredentialProvider(this, morpheus)
		this.pluginProviders.put("ciphertrust" ,cipherTrustCredentialProvider)

		ThalesCipherTrustCypherKeyProvider cipherTrustKeyCypherProvider = new ThalesCipherTrustCypherKeyProvider(this, morpheus)
		this.pluginProviders.put("ciphertrust-key", cipherTrustKeyCypherProvider)

		ThalesCipherTrustCypherSecretProvider cipherTrustSecretCypherProvider = new ThalesCipherTrustCypherSecretProvider(this, morpheus)
		this.pluginProviders.put("ciphertrust-secret", cipherTrustSecretCypherProvider)


		this.settings << new OptionType (
                name: 'Service Url',
                code: 'ciphertrust-service-url',
                fieldName: 'keysServiceUrl',
                displayOrder: 0,
                fieldLabel: 'Service Url',
                helpText: 'The full URL of the Thales CipherTrust Manager endpoint. Example: https://ciphertrust.domain/api/',
                required: true,
                inputType: OptionType.InputType.TEXT
        )

		//for keys provider
        this.settings << new OptionType (
                name: 'Keys Username',
                code: 'ciphertrust-keys-service-username',
                fieldName: 'keysServiceUsername',
                displayOrder: 1,
                fieldLabel: 'Keys API Username',
                helpText: 'Keys API Username',
                required: true,
                inputType: OptionType.InputType.TEXT
        )
        this.settings << new OptionType (
                name: 'Keys Password',
                code: 'ciphertrust-keys-service-password',
                fieldName: 'keysServicePassword',
                displayOrder: 2,
                fieldLabel: 'Keys API Password',
                helpText: 'Keys API Password',
                required: true,
                inputType: OptionType.InputType.PASSWORD
        )
        this.settings << new OptionType (
                name: 'Keys Domain',
                code: 'ciphertrust-keys-service-domain',
                fieldName: 'keysServiceDomain',
                displayOrder: 3,
                fieldLabel: 'CipherTrust Domain',
                helpText: 'CipherTrust Domain',
                required: false,
				defaultValue: 'root',
                inputType: OptionType.InputType.TEXT
        )

		//for secrets provider
		this.settings << new OptionType(
				name: 'Secrets User',
				code: 'ciphertrust-secrets-service-username',
				inputType: OptionType.InputType.TEXT,
				fieldName: 'secretsServiceUsername',
				fieldLabel: 'API Access Id',
				displayOrder: 4,
				helpText: 'The API Access Id'
		)
		this.settings << new OptionType(
				name: 'API Access Key',
				code: 'ciphertrust-secrets-service-password',
				inputType: OptionType.InputType.PASSWORD,
				fieldName: 'secretsServicePassword',
				fieldLabel: 'API Access Key',
				displayOrder: 5,
				helpText: 'The API Access Key'
		)
		this.settings << new OptionType(
				name: 'Secret Path',
				code: 'ciphertrust-secret-service-path',
				inputType: OptionType.InputType.TEXT,
				defaultValue: ThalesCipherTrustCredentialProvider.DEFAULT_SECRET_PATH,
				fieldName: 'secretsServicePath',
				fieldLabel: 'Secret Path',
				displayOrder: 6
		)


	}

	/**
	 * Called when a plugin is being removed from the plugin manager (aka Uninstalled)
	 */
	@Override
	void onDestroy() {
		//nothing to do for now
	}
	
	public String getUrl() {
		def rtn
		def settings = getSettings(this.morpheus, this)
		if (settings.keysServiceUrl) {
			rtn = settings.keysServiceUrl
			rtn = rtn.replace(" ", "");
			if(!rtn.endsWith('/')) {
				rtn = rtn + '/'
			}
		}
		return rtn
	}

	public String getServiceUsername() {
		def rtn
		def settings = getSettings(this.morpheus, this)
		if (settings.keysServiceUsername) {
			rtn = settings.keysServiceUsername
			rtn = rtn.replace(" ", "");
		}
		return rtn
	}

	public String getServicePassword() {
		def rtn
		def settings = getSettings(this.morpheus, this)
		if (settings.keysServicePassword) {
			rtn = settings.keysServicePassword
		}
		return rtn
	}

	public String getDomain() {
		def rtn
		def settings = getSettings(this.morpheus, this)
		if (settings.keysServiceDomain) {
			rtn = settings.keysServiceDomain
			rtn = rtn.replace(" ", "");
		}
		return rtn
	}

	public String getSecretsServiceUsername() {
		def rtn
		def settings = getSettings(this.morpheus, this)
		if (settings.secretsServiceUsername) {
			rtn = settings.secretsServiceUsername
			rtn = rtn.replace(" ", "");
		}
		return rtn
	}

	public String getSecretsServicePassword() {
		def rtn
		def settings = getSettings(this.morpheus, this)
		if (settings.secretsServicePassword) {
			rtn = settings.secretsServicePassword
		}
		return rtn
	}

	public String getSecretsServicePath() {
		def rtn
		def settings = getSettings(this.morpheus, this)
		if (settings.secretsServicePath) {
			rtn = settings.secretsServicePath
		}
		return rtn
	}




	private getSettings(MorpheusContext morpheusContext, Plugin plugin) {
		def settingsOutput = null
		try {
			def settings = morpheusContext.getSettings(plugin)
			settings.subscribe(
				{ outData -> 
					settingsOutput = outData
				},
				{ error ->
				  log.error("Error subscribing to settings")
				}
			)
		} catch(Exception e) {
			log.error("Error obtaining CipherTrust plugin settings")
		}
		if (settingsOutput) {
			JsonSlurper slurper = new JsonSlurper()
			return slurper.parseText(settingsOutput)
		} else {
			return [:]
		}
	}
}
