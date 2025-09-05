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
		this.pluginProviders.put("ciphertrust-cypher", cipherTrustKeyCypherProvider)

		ThalesCipherTrustCypherSecretProvider cipherTrustSecretCypherProvider = new ThalesCipherTrustCypherSecretProvider(this, morpheus)
		this.pluginProviders.put("ciphertrust-cypher", cipherTrustSecretCypherProvider)


		this.settings << new OptionType (
                name: 'Thales CipherTrust Service Url',
                code: 'ciphertrust-cypher-plugin-url',
                fieldName: 'cipherTrustPluginServiceUrl',
                displayOrder: 0,
                fieldLabel: 'Thales CipherTrust Url',
                helpText: 'The full URL of the Thales CipherTrust Manager endpoint. Example: https://ciphertrust.domain/api/',
                required: true,
                inputType: OptionType.InputType.TEXT
        )

		//for keys provider
        this.settings << new OptionType (
                name: 'Thales CipherTrust Username',
                code: 'ciphertrust-cypher-plugin-serviceusername',
                fieldName: 'cipherTrustPluginServiceUsername',
                displayOrder: 1,
                fieldLabel: 'CipherTrust API Username',
                helpText: 'CipherTrust API Username',
                required: true,
                inputType: OptionType.InputType.TEXT
        )
        this.settings << new OptionType (
                name: 'Thales CipherTrust Password',
                code: 'ciphertrust-cypher-plugin-servicepassword',
                fieldName: 'cipherTrustPluginServicePassword',
                displayOrder: 2,
                fieldLabel: 'CipherTrust API Password',
                helpText: 'CipherTrust API Password',
                required: true,
                inputType: OptionType.InputType.PASSWORD
        )
        this.settings << new OptionType (
                name: 'Thales CipherTrust Domain',
                code: 'ciphertrust-cypher-plugin-serviceSlave',
                fieldName: 'cipherTrustPluginServiceSlave',
                displayOrder: 3,
                fieldLabel: 'CipherTrust Domain',
                helpText: 'CipherTrust Domain',
                required: false,
				defaultValue: 'root',
                inputType: OptionType.InputType.TEXT
        )

		//for secrets provider
		this.settings << new OptionType(
				code: 'ciphertrust.serviceUsername',
				name: 'API Access Id',
				inputType: OptionType.InputType.TEXT,
				fieldName: 'secretsServiceUsername',
				fieldLabel: 'API Access Id',
				fieldContext: 'domain',
				displayOrder: 1,
				helpText: 'The API Access Id'
		)
		this.settings << new OptionType(
				code: 'ciphertrust.servicePassword',
				name: 'API Access Key',
				inputType: OptionType.InputType.PASSWORD,
				fieldName: 'secretsServicePassword',
				fieldLabel: 'API Access Key',
				fieldContext: 'domain',
				displayOrder: 2,
				helpText: 'The API Access Key'
		)
		new OptionType(
				code: 'ciphertrust.servicePath',
				name: 'Secret Path',
				inputType: OptionType.InputType.TEXT,
				defaultValue: ThalesCipherTrustCredentialProvider.DEFAULT_SECRET_PATH,
				fieldName: 'secretsServicePath',
				fieldLabel: 'Secret Path',
				fieldContext: 'domain',
				displayOrder: 3
		)


	}

	/**
	 * Called when a plugin is being removed from the plugin manager (aka Uninstalled)
	 */
	@Override
	void onDestroy() {
		//nothing to do for now
	}
	
	public  String getUrl() {
		def rtn
		def settings = getSettings(this.morpheus, this)
		if (settings.cipherTrustPluginServiceUrl) {
			rtn = settings.cipherTrustPluginServiceUrl
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
		if (settings.cipherTrustPluginServiceUsername) {
			rtn = settings.cipherTrustPluginServiceUsername
			rtn = rtn.replace(" ", "");
		}
		return rtn
	}

	public String getServicePassword() {
		def rtn
		def settings = getSettings(this.morpheus, this)
		if (settings.cipherTrustPluginServicePassword) {
			rtn = settings.cipherTrustPluginServicePassword
		}
		return rtn
	}

	public String getDomain() {
		def rtn
		def settings = getSettings(this.morpheus, this)
		if (settings.cipherTrustPluginServiceSlave) {
			rtn = settings.cipherTrustPluginServiceSlave
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
