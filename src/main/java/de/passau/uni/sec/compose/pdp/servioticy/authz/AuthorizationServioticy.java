package de.passau.uni.sec.compose.pdp.servioticy.authz;




import java.io.IOException;
import java.util.HashMap;
import java.util.List;
import java.util.Map;
import java.lang.String;

import org.apache.http.client.methods.CloseableHttpResponse;
import org.apache.http.util.EntityUtils;

import com.fasterxml.jackson.core.JsonProcessingException;
import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.ObjectMapper;

import de.passau.uni.sec.compose.pdp.servioticy.PermissionCacheObject;
import de.passau.uni.sec.compose.pdp.servioticy.exception.PDPServioticyException;
import de.passau.uni.sec.compose.pdp.servioticy.idm.IDMCommunicator;

public class AuthorizationServioticy 
{
	private static final String IDM_USER_SECTION = "id";


	/**
	 * Verifies the policy for the currnt SO and a SU
	 *
	 * @param security_metadata_SO_current
	 * @param security_metadata_of_the_SU
	 * @param cache
	 * @param idmHost
	 * @param idmUser
	 * @param idmPass
	 * @param idmPort
	 * @return returns true or false in the "Permission" entry of the cach object depending on the policy evaluation
	 */
	public PermissionCacheObject verifyGetData( String access_token_user ,
			JsonNode security_metadata_SO_current,
			JsonNode security_metadata_of_the_SU, PermissionCacheObject cache,
			String idmHost, String idmUser, String idmPass,int idmPort) throws PDPServioticyException {
		
		Map<String, Object> tempMapCache = new HashMap<String, Object>();

		// Check if parameters to connect to IDM exist
	 	 PermissionCacheObject obj = new PermissionCacheObject();
	 	 if(idmUser==null || idmPass == null || idmHost ==null || idmPort<0) {
	 		throw new PDPServioticyException(500, "Not enough parameters to talk to the IDM ", "Not enough parameters to talk to IDM");
		 }
		
		 // Connect to IDM if no information is in the cach object
		 String response = "";
		 if (cache.getCache() == null) {		
		 	 // Check if user is allowed to get data from the SO
			 IDMCommunicator com = new IDMCommunicator(idmUser, idmPass, idmHost, idmPort);
			 try {
				 response = com.getInformationForUser(access_token_user);
			 }
			 catch (PDPServioticyException e){
				 obj.setPermission(false);
				 obj.setCache(e);
				 return obj;
			 }
			// Parse response
		    ObjectMapper mapperUser = new ObjectMapper();
		    JsonNode user_data = null;
			try {
				user_data = mapperUser.readTree(response);
			} catch (JsonProcessingException e1) {
				user_data = null;
			} catch (IOException e1) {
				user_data = null;
			}
			JsonNode userSO = user_data.findValue(IDM_USER_SECTION);
			tempMapCache.put("UserId", userSO.toString());
			cache.setCache(tempMapCache);
			
		 }
		 

		// Check policies
		boolean poleval = evaluatePolicy(security_metadata_of_the_SU, cache.getUserId());
		// Set cache
		 //tempMap.put("UserMetaData", response);
		obj.setPermission(poleval);
		obj.setCache(cache.getCache());
		return obj;				
	}

	/**
	 * Checks the policy during dispatching 
	 *
	 * @param security_metadata_SO (destination SO)
	 * @param security_metadata_of_the_SU (input SU)
	 * @param idmHost
	 * @param idmUser
	 * @param idmPass
	 * @param idmPort
	 * @return returns true or false in the "Permission" entry of the cach object depending on the policy evaluation
	 */
	public PermissionCacheObject verifyGetDataDispatch(
			JsonNode security_metadata_SO_destination,
			JsonNode security_metadata_of_the_SU,
			String idmHost, String idmUser, String idmPass,int idmPort) throws PDPServioticyException {

	 		PermissionCacheObject obj = new PermissionCacheObject();
 			if (security_metadata_SO_destination == null || security_metadata_of_the_SU == null)
 			{
				obj.setPermission(false);
				return obj;

 			}

			// Add check if it is the same SO if yes return true. 
			// http://docs.servioticysecurity.apiary.io/

			boolean evaluation = evaluatePolicy(security_metadata_SO_destination, security_metadata_of_the_SU);
			obj.setPermission(evaluation);
			return obj;

				
	}







	/**
	 * Checks the policy during dispatching 
	 *
	 * @param security_metadata_SO (destination SO)
	 * @param security_metadata_of_the_SU (input SU)
	 * @return returns true or false depending on the policy evaluation
	 */
	private boolean evaluatePolicy(JsonNode SO, JsonNode inputSU){
		boolean ret = false;
		// Get userids
		JsonNode userSO = SO.findValue("owner_id");
		if (userSO == null) {System.out.println("User SO no value Node");return false;}
		JsonNode userSU = inputSU.findValue("owner_id");
		if (userSU == null) {System.out.println("User SU no value Node");return false;}
		// Get policys (works if it is inside the security section or if it is at the highest level)
		JsonNode policySU = inputSU.findValue("policy");
		JsonNode policySO = SO.findValue("policy");
		// If no policy section is found return false
		if (policySO == null || policySU == null)
		{
			System.out.println("Policy null");
			return false;
		}
		
		// Interate over the flows for the source policy (SU)
		List<JsonNode> flowsSU = inputSU.findValues("flow");
		for (JsonNode currentFlow : flowsSU)
		{
			// Get target
			JsonNode targetSU = currentFlow.get("target");
			if (targetSU == null) {continue;}
			// Evaluate policy of SU
			JsonNode targetFlowSU = policySU;
			if (targetSU.asText().contains("userid/"))
			{
				//System.out.println("User SU: " + targetSU.asText() + " " + userSO.toString());
				if (targetSU.asText().equals("userid/"+ userSO.toString().substring(1,userSO.toString().length()-1)))
				{
					ret = true;
				}
				else {
					return false;
				}
			}
			else if (targetSU.asText().equals("entities"))
			{
				JsonNode forallSU = currentFlow.get("forall");
				if (forallSU == null){continue;}		
				if (forallSU.asText().equals("entities"))
				{
					ret = true;
				} 
				else {
					return false;
				} 
			}
		}
		// Interate over the flows for the destination policies (SO)
		List<JsonNode> flowsSO = SO.findValues("flow");
		for (JsonNode currentFlow : flowsSO)
		{
			// Get source
			JsonNode sourceSO = policySO.get("source");
			if (sourceSO == null) {continue;} //.isValueNode() 
			// Evaluate policy of SU
			JsonNode sourceFlowSO = policySO;
			if (sourceSO.asText().contains("userid/"))
			{
				if (sourceSO.asText().equals("userid/"+ userSU.toString().substring(1,userSU.toString().length()-1)))
				{
					ret = true;
				}
				else {
					return false;
				}
			}
			else if (sourceSO.asText().equals("entities"))
			{
				JsonNode forallSO = currentFlow.get("forall");		
				if (forallSO.asText().equals("entities"))
				{
					ret = true;
				} 
				else {
					return false;
				} 
			}
		}
		return ret;
	}

	/**
	 * Checks the policy for geting SUs of a SO 
	 *
	 * @param security_metadata_SU 
	 * @param user that wants to access the SU
	 * @return returns true or false depending on the policy evaluation
	 */
	private boolean evaluatePolicy(JsonNode SU, String user){
		boolean ret = false;
		// Get policys (works if it is inside the security section or if it is at the highest level)
		JsonNode policySU = SU.findValue("policy");
		// If no policy section is found return false
		if (policySU == null)
		{
			System.out.println("Policy null");
			return false;
		}
		
		// Interate over the flows for the source policy (SU)
		List<JsonNode> flowsSU = SU.findValues("flow");
		for (JsonNode currentFlow : flowsSU)
		{
			// Get target
			JsonNode targetSU = currentFlow.get("target");
			if (targetSU == null) {continue;}
			// Evaluate policy of SU
			JsonNode targetFlowSU = policySU;
			if (targetSU.asText().contains("userid/"))
			{
				System.out.println("User SU: " + targetSU.asText() + " " + user);
				if (targetSU.asText().equals("userid/"+ user))
				{
					ret = true;
				}
				else {
					return false;
				}
			}
			else if (targetSU.asText().equals("entities"))
			{
				JsonNode forallSU = currentFlow.get("forall");
				if (forallSU == null){continue;}		
				if (forallSU.asText().equals("entities"))
				{
					ret = true;
				} 
				else {
					return false;
				} 
			}
		}
		return ret;
	}


}








