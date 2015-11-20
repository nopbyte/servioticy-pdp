package de.passau.uni.sec.compose.pdp.servioticy.policy;

import java.io.File;
import java.io.FileNotFoundException;
import java.io.FileReader;
import java.io.Reader;

import javax.script.ScriptEngine;
import javax.script.ScriptEngineManager;
import javax.script.ScriptException;
import java.io.InputStream;
import java.io.BufferedReader;
import java.io.IOException;
import java.io.InputStreamReader;

import java.security.CodeSource;
import java.net.URL;
import java.util.zip.ZipEntry;
import java.util.zip.ZipInputStream;
import com.fasterxml.jackson.databind.JsonNode;

import de.passau.uni.sec.compose.pdp.servioticy.PermissionCacheObject;
import de.passau.uni.sec.compose.pdp.servioticy.idm.IDMCommunicator;

public class PolicyEvaluation {
	private boolean error;
    private ScriptEngineManager manager = new ScriptEngineManager();
    private ScriptEngine engine = manager.getEngineByName("JavaScript");



	private static String getStringFromInputStream(InputStream is) {

		if (is == null){
			System.out.println("Empty inout stream");
			return "";
		}

		BufferedReader br = null;
		StringBuilder sb = new StringBuilder();

		String line;
		try {

			br = new BufferedReader(new InputStreamReader(is));
			while ((line = br.readLine()) != null) {
				sb.append("\n" + line);
			}

		} catch (Exception e) {
			e.printStackTrace();
		} finally {
			if (br != null) {
				try {
					br.close();
				} catch (Exception e) {
					e.printStackTrace();
				}
			}
		}

		return sb.toString();

	}




	/*
	 * Constructor, loads the main files and all locks (including the registration of the logs)
	 */
	public PolicyEvaluation() {
		Boolean inJar = false;
	  error = false;
		String currentJsCode = "";

		try {
			CodeSource src = PolicyEvaluation.class.getProtectionDomain().getCodeSource();
			if (src != null) {
				URL jar = src.getLocation();
				ZipInputStream zip = null;
				zip = new ZipInputStream(jar.openStream());
				while(true) {
					ZipEntry e = null;
					e = zip.getNextEntry();
					if (e == null)
						break;
					inJar = true;
					String name = e.getName();
	    			if (name.startsWith("js/de/passau/uni/sec/compose/Policy/") && name.endsWith(".js") && name.startsWith("js/de/passau/uni/sec/compose/Policy/Locks/") == false && name.contains("postLoadInit") == false) {
	    				System.out.println("jar " + name);
	    				ClassLoader classloader = Thread.currentThread().getContextClassLoader();
	        		   InputStream resource = PolicyEvaluation.class.getResourceAsStream("/"+ name);
	        		   currentJsCode = getStringFromInputStream(resource);
	        		   //System.out.println("Data: " + currentJsCode);
	        		   try {
	        			   engine.eval(currentJsCode);
	        		   } catch (Exception eJS) {
	        			   System.out.println("PDP-JS: " + eJS);
	        			   error = true;
	        		   }
	    			}
				}
			}
			else {
				   System.out.println("PDP-JS could not get the list of files");
    			   error = true;
			}
		} catch (Exception e2) {
			   System.out.println("PDP-JS could not get the list of files: " + e2);
			   error = true;
		}
		if (inJar == true){
			// Locks
			try {
				CodeSource src = PolicyEvaluation.class.getProtectionDomain().getCodeSource();
				if (src != null) {
					URL jar = src.getLocation();
					ZipInputStream zip = null;
					zip = new ZipInputStream(jar.openStream());
					while(true) {
						ZipEntry e = null;
						e = zip.getNextEntry();
						if (e == null)
							break;
						String name = e.getName();
		    			if (name.startsWith("js/de/passau/uni/sec/compose/Policy/Locks/") && name.endsWith(".js")) {
		    				System.out.println("jar " + name);
		    				ClassLoader classloader = Thread.currentThread().getContextClassLoader();
		        		   InputStream resource = PolicyEvaluation.class.getResourceAsStream("/"+ name);//"/js/de/passau/uni/sec/compose/Policy/Flow.js");
		        		   currentJsCode = getStringFromInputStream(resource);
		        		   //System.out.println("Data: " + currentJsCode);
		        		   try {
		        			   engine.eval(currentJsCode);
		        		   } catch (Exception eJS) {
		        			   System.out.println("PDP-JS: " + eJS);
		        			   error = true;
		        		   }
		    			}
					}
				}
				else {
					   System.out.println("PDP-JS could not get the list of files");
	    			   error = true;
				}
			} catch (Exception e2) {
				   System.out.println("PDP-JS could not get the list of files: " + e2);
				   error = true;
			}
			// Post load init
			ClassLoader classloader = Thread.currentThread().getContextClassLoader();
					System.out.println("jar /js/de/passau/uni/sec/compose/Policy/postLoadInit.js");
			   InputStream resource = PolicyEvaluation.class.getResourceAsStream("/js/de/passau/uni/sec/compose/Policy/postLoadInit.js");
			   currentJsCode = getStringFromInputStream(resource);
			   try {
				   engine.eval(currentJsCode);
			   } catch (Exception eJS) {
				   System.out.println("PDP-JS: " + eJS);
				   error = true;
			   }
			 }

			 if (inJar == false){
				 // Load files local
		    try{
		    // Load files
		    File polFolder = new File("src/main/resources/js/de/passau/uni/sec/compose/Policy/");
		    File[] polFiles = polFolder.listFiles();
		    for (File i : polFiles){
		    	if (i.isFile() && i.getName().toLowerCase().endsWith(".js") && (i.getName().toLowerCase().endsWith("postloadinit.js") == false)){
		    		System.out.println(i);
		    		Reader poReaderTemp;
					try {
						poReaderTemp = new FileReader(i);
			    		engine.eval(poReaderTemp);
					} catch (Exception e) {
						System.out.println("PDP-JS: " + e);
						error = true;
					}
		    	}
		    }
		    // Load logs
		    File locFolder = new File("src/main/resources/js/de/passau/uni/sec/compose/Policy/Locks/");
		    File[] locFiles = locFolder.listFiles();
		    for (File i : locFiles){
		    	if (i.isFile() && i.getName().toLowerCase().endsWith(".js")){
		    		System.out.println(i);
		    		Reader poReaderTemp;
					try {
						poReaderTemp = new FileReader(i);
			    		engine.eval(poReaderTemp);
					} catch (Exception e) {
						System.out.println("PDP-JS: " + e);
						error = true;
					}
		    	}
		    }
		    // Register logs
		    File testFile = new File("src/main/resources/js/de/passau/uni/sec/compose/Policy/postLoadInit.js");
		    Reader testReader;
			try {
				testReader = new FileReader(testFile);
			    engine.eval(testReader);
			} catch (Exception e) {
				System.out.println("PDP-JS: " + e);
				error = true;
			}
		}catch (Exception e2){
			System.out.println("PDP-JS: " + e2);
		}
	}
}

	/*
	 * Checks the policy of SO and a SU (SU that is processed by a SO)
	 */
	public boolean checkFlow(JsonNode SO, JsonNode inputSU, String stream){
		boolean ret = false;
		System.out.println("Check access with init-error:" + error);
		String code = "";
		// Get policys (works if it is inside the security section or if it is at the highest level)
		JsonNode policySU = inputSU.findValue("policy");
		JsonNode policySO = SO.findValue("policy");
		// If no policy section is found return false
		if (policySO == null || policySU == null)
		{
			System.out.println("DPD-JS: no Policy found");
			return false;
		}
		// Build entity with the stream
		JsonNode secSO = SO.findValue("security");
		if (secSO == null){
			secSO = SO;
		}
		JsonNode secSU = inputSU.findValue("security");
		if (secSU == null){
			secSU = inputSU;
		}
		JsonNode idSO = secSO.get("id");
		String entity = "{\"type\" : \"so\", \"id\":\"" + idSO.asText() + "\",\"stream\": \""+ stream + "\"}";
		System.out.println("Entitiy: " + entity);
		System.out.println("context: " + "{subject : {type : 'so', data:" + secSO.toString() + "},object : {type : 'su',data:" + secSU.toString() + "}};");


		// Generate analysis code
		code += "cont = new Context({subject : {type : 'so', data:" + secSO.toString() + "},object : {type :'su',data :" + secSU.toString() + "}});";
		//code += "cont = {subject : " + secSO.toString() + ",object : " + secSU.toString() + "};"; // context.subject = SO.Security context.object = SU.security
		code += "entDes = new Entity(" + entity + ");";
		code += "pSet = new PolicySet(" + policySO.toString() +");";
		//code += "print(\"PolicySet \"+JSON.stringify(pSet));";
		code += "pSO = pSet.getBestMatchPolicy(entDes);";
		code += "print(\"Best match \"+JSON.stringify(pSO));";
		code += "print(\"\\n\");";
		code += "pSU = new Policy(" + policySU.toString()+");";
		code += "print(\"pSU \"+JSON.stringify(pSU));";
		code += "print(\"\\n\");";
		code += "ret = pSU.checkFlow(pSO, Policy.Direction.INCOMING, cont);";
		code += "print(\"ret Flow check\"+JSON.stringify(ret));";
		code += "ret = ret.result";
		// Evaluate code
	    try {
			engine.eval(code);
			Object retJS = engine.get("ret");
			System.out.println("\nRET in Java: " + retJS);
			if (retJS instanceof Boolean){
				ret = (Boolean) retJS;
			} else {ret = false;};
		} catch (ScriptException e) {
			System.out.println("PDP-JS: " + e);
			ret = false;
		}
		return ret;
	}

	/*
	 * Checks the policy of SU against a user
	 */
	public boolean checkAccess(JsonNode SU, String user, JsonNode userInfo){
		boolean ret = false;
		System.out.println("Check access with init-error:" + error);
		String code = "";
		// Get policys (works if it is inside the security section or if it is at the highest level)
		JsonNode policySU = SU.findValue("policy");
		// If no policy section is found return false
		if (policySU == null)
		{
			System.out.println("DPD-JS: no Policy found");
			return false;
		}

		// Build entity
		String entity = "{\"type\" : \"user\", \"id\":\"" + user + "\"}";
		System.out.println("Entitiy: " + entity);
		// context.subsject = {IDM result} contect.object = SU.security
		JsonNode secSU = SU.findValue("security");
		if (secSU == null){
			secSU = SU;
		}


		// Generate analysis code
		code += "cont = new Context({subject : {type : 'user', data:" + userInfo.toString() + "},object : {type : 'su',data:" + secSU.toString() + "}});";
		//code += "cont = {subject : " + userInfo.toString() + ",object : " + secSU.toString() + "};";
		code += "entDes = new Entity(" + entity + ");";
		code += "print(\"cont \"+JSON.stringify(cont));";
		code += "print(\"\\n\");";
		code += "pSU = new Policy(" + policySU.toString()+");";
		code += "print(\"pSU \"+JSON.stringify(pSU));";
		code += "print(\"\\n\");";
		code += "ret = pSU.checkAccess(entDes, Policy.Operation.READ, cont);"; //TODO add cont
		code += "print(\"ret check Access\"+JSON.stringify(ret));";
		code += "ret = ret.result";
		// Evaluate code
	    try {
			engine.eval(code);
			Object retJS = engine.get("ret");
			System.out.println("\nRET in Java: " + retJS);
			if (retJS instanceof Boolean){
				ret = (Boolean) retJS;
			} else {ret = false;};
	    } catch (ScriptException e) {
			System.out.println("PDP-JS: " + e);
			ret = false;
		}
		return ret;
	}

	
	
	/*
	 * Checks the policy of SO against a user // TODO change for SO
	 */
	public boolean checkAccessSO(JsonNode SO, String user, JsonNode userInfo){
		boolean ret = false;
		System.out.println("Check access with init-error:" + error);
		String code = "";
		// Get policys (works if it is inside the security section or if it is at the highest level)
		JsonNode policySO = SO.findValue("policy");
		// If no policy section is found return false
		if (policySO == null)
		{
			System.out.println("DPD-JS: no Policy found");
			return false;
		}

		JsonNode secSO = SO.findValue("security");
		if (secSO == null){
			secSO = SO;
		}
		
		// Build entity
		JsonNode idSO = secSO.get("id");
		String entity = "{\"type\" : \"user\", \"id\":\"" + user + "\"}";
		String entitySO = "{\"type\" : \"so\", \"id\":" + idSO + "}";
		System.out.println("EntitiySO: " + entitySO);
		System.out.println("SO sec: " + secSO.toString());
		//System.out.println("User: " + userInfo.toString());

		// context.subsject = {IDM result} contect.object = SU.security



		// Generate analysis code
		code += "cont = new Context({subject : {type : 'user', data:" + userInfo.toString() + "},object : {type : 'so',data:" + secSO.toString() + "}});";
		//code += "cont = {subject : " + userInfo.toString() + ",object : " + secSU.toString() + "};";
		code += "print(\"\\n\");";
		code += "print(\"cont \"+JSON.stringify(cont));";
		code += "print(\"\\n\");";
		code += "entDes = new Entity(" + entitySO + ");";
		code += "print(\"\\n3\");";
		code += "pSet = new PolicySet(" + policySO.toString() +");";
		code += "print(\"\\n\");";
		code += "pSO = pSet.getBestMatchPolicy(entDes);";
		//code += "pSO = new Policy(pSO.flows)";
		//code += "pSO = new Policy(" + policySO.get("flows").toString()+");";
		code += "entDes = new Entity(" + entity + ");";
		code += "print(\"pSO \"+JSON.stringify(pSO));";
		code += "print(\"\\n\");";
		code += "ret = pSO.checkAccess(entDes, Policy.Operation.READ, cont);";
		code += "print(\"ret check Access\"+JSON.stringify(ret));";
		code += "ret = ret.result";
		// Evaluate code
	    try {
			engine.eval(code);
			Object retJS = engine.get("ret");
			System.out.println("\nRET in Java: " + retJS);
			if (retJS instanceof Boolean){
				ret = (Boolean) retJS;
			} else {ret = false;};
	    } catch (ScriptException e) {
			System.out.println("PDP-JS: " + e);
			ret = false;
		}
		return ret;
	}
	
	
	
	/*
	 * Checks the policy of SU against a user
	 */
	public boolean checkWriteAccess(JsonNode SU, String user, JsonNode userInfo){
		boolean ret = false;
		System.out.println("Check access with init-error:" + error);
		String code = "";
		// Get policys (works if it is inside the security section or if it is at the highest level)
		JsonNode policySU = SU.findValue("policy");
		// If no policy section is found return false
		if (policySU == null)
		{
			System.out.println("DPD-JS: no Policy found");
			return false;
		}

		// Build entity
		String entity = "{\"type\" : \"user\", \"id\":\"" + user + "\"}";
		System.out.println("Entitiy: " + entity);
		// context.subsject = {IDM result} contect.object = SU.security
		JsonNode secSU = SU.findValue("security");
		if (secSU == null){
			secSU = SU;
		}


		// Generate analysis code
		code += "cont = new Context({subject : {type : 'user', data:" + userInfo.toString() + "},object : {type : 'su',data:" + secSU.toString() + "}});";
		//code += "cont = {subject : " + userInfo.toString() + ",object : " + secSU.toString() + "};";
		code += "entDes = new Entity(" + entity + ");";
		code += "print(\"cont \"+JSON.stringify(cont));";
		code += "print(\"\\n\");";
		code += "pSU = new Policy(" + policySU.toString()+");";
		code += "print(\"pSU \"+JSON.stringify(pSU));";
		code += "print(\"\\n\");";
		code += "ret = pSU.checkAccess(entDes, Policy.Operation.WRITE, cont);"; //TODO add cont
		code += "print(\"ret check Access\"+JSON.stringify(ret));";
		code += "ret = ret.result";
		// Evaluate code
	    try {
			engine.eval(code);
			Object retJS = engine.get("ret");
			System.out.println("\nRET in Java: " + retJS);
			if (retJS instanceof Boolean){
				ret = (Boolean) retJS;
			} else {ret = false;};
	    } catch (ScriptException e) {
			System.out.println("PDP-JS: " + e);
			ret = false;
		}
		return ret;
	}

	/*
	 * Checks the policy of SO against a user WTP
	 */
	public boolean checkWriteAccess(JsonNode SO, String user, JsonNode userInfo, String stream){
		boolean ret = false;
		System.out.println("Check access with init-error:" + error);
		String code = "";
		// Get policys (works if it is inside the security section or if it is at the highest level)
		JsonNode policySO = SO.findValue("policy");
		// If no policy section is found return false
		if (policySO == null)
		{
			System.out.println("DPD-JS: no Policy found");
			return false;
		}

		JsonNode secSO = SO.findValue("security");
		if (secSO == null){
			secSO = SO;
		}


		// Build entity
		JsonNode idSO = secSO.get("id");
		String entitySO;
		if (stream != null && stream != ""){
			entitySO = "{\"type\" : \"so\", \"id\":\"" + idSO.asText() + "\",\"stream\": \""+ stream + "\"}";
		} else {
			entitySO = "{\"type\" : \"so\", \"id\":\"" + idSO.asText() + "\"}";

		}
		String entityU = "{\"type\" : \"user\", \"id\":\"" + user + "\"}";

		System.out.println("Entitiy: " + entitySO);
		// context.subsject = {IDM result} contect.object = SU.security

		// Generate analysis code
		code += "cont = new Context({subject : {type : 'user', data:" + userInfo.toString() + "},object : {type : 'so',data:" + secSO.toString() + "}});";
		code += "entDes = new Entity(" + entitySO + ");";

		code += "pSet = new PolicySet(" + policySO.toString() +");";
		//code += "print(\"PolicySet \"+JSON.stringify(pSet));";
		code += "pSO = pSet.getBestMatchPolicy(entDes);";
		code += "entDes = new Entity(" + entityU + ");";
		code += "print(\"cont \"+JSON.stringify(cont));";
		code += "print(\"\\n\");";
		code += "print(\"pSO \"+JSON.stringify(pSU));";
		code += "print(\"\\n\");";
		code += "ret = pSO.checkAccess(entDes, Policy.Operation.WRITE, cont);"; //TODO add cont
		code += "print(\"ret check Access\"+JSON.stringify(ret));";
		code += "ret = ret.result";
		// Evaluate code
	    try {
			engine.eval(code);
			Object retJS = engine.get("ret");
			System.out.println("\nRET in Java: " + retJS);
			if (retJS instanceof Boolean){
				ret = (Boolean) retJS;
			} else {ret = false;};
	    } catch (ScriptException e) {
			System.out.println("PDP-JS: " + e);
			ret = false;
		}
		return ret;
	}
}
