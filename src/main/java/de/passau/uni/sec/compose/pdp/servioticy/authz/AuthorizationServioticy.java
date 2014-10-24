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
import com.fasterxml.jackson.databind.node.ObjectNode;

import de.passau.uni.sec.compose.pdp.servioticy.PermissionCacheObject;
import de.passau.uni.sec.compose.pdp.servioticy.exception.PDPServioticyException;
import de.passau.uni.sec.compose.pdp.servioticy.idm.IDMCommunicator;
import de.passau.uni.sec.compose.pdp.servioticy.idm.IdentityVerifier;

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
		
		Map<String, Object> internalCache = new HashMap<String, Object>();

		// Check if parameters to connect to IDM exist
	 	 if(idmUser==null || idmPass == null || idmHost ==null || idmPort<0) {
	 		throw new PDPServioticyException(500, "Not enough parameters to talk to the IDM ", "Not enough parameters to talk to IDM");
		 }
		 if(security_metadata_of_the_SU ==null || security_metadata_SO_current ==null)
				throw new PDPServioticyException(500, "No security metadata for the sensor update or service object", "Not enough security metadata for the sensor update or service object");
		 // Connect to IDM if no information is in the cach objecttempMapCache
		 String response = "";
		 if (cache ==null || cache.getCache() == null) {	
			 if(cache==null)
				 cache = new PermissionCacheObject();
		 	 // Check if user is allowed to get data from the SO
			 if(cache.getCache()!=null)
				 internalCache = (Map<String, Object>) cache.getCache();
			 if(((Boolean)internalCache.get("wrong:"+access_token_user)).booleanValue())
			 {
				 cache.setPermission(false);
				 return cache;
			 }
			 IDMCommunicator com = new IDMCommunicator(idmUser, idmPass, idmHost, idmPort);
			 try {
				 response = com.getInformationForUser(access_token_user);
				 if(response ==null)
				 {
					 internalCache.put("wrong:"+access_token_user, new Boolean(true));
					 cache.setPermission(false);
					 return cache;
				 }
				 internalCache.put("wrong:"+access_token_user, new Boolean(false));
			 }
			 catch (PDPServioticyException e){
				 cache.setPermission(false);
				 cache.setCache(e);
				 return cache;
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
			if (userSO != null){
				internalCache.put("UserId", userSO.asText());
			}
			cache.setCache(internalCache);
		 }

		 JsonNode owner = security_metadata_SO_current.findValue("owner_id");
		 if(owner==null)
			 throw new PDPServioticyException(500, "owner not found in service object metadata", "owner_id not found inside security metadata for service object:"+security_metadata_of_the_SU);
		 String soOwner = owner.asText();
		 boolean poleval = evaluatePolicy(security_metadata_of_the_SU, cache.getUserId());
		 cache.setPermission(poleval);
		return cache;		
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
	    	// Build Security Meta-Data
			Map<String, Object> tempMapCache = new HashMap<String, Object>();
	    	ObjectMapper mapper = new ObjectMapper();
	    	//ObjectNode node =  mapper.getNodeFactory().objectNode();
	    	ObjectNode securityData = mapper.getNodeFactory().objectNode();
	    	JsonNode policies = security_metadata_SO_destination.findPath("policy");
	    	if (policies !=  null){
		    	securityData.put("policy", policies);
		    	//node.put("security", securityData);
		    }
	    	JsonNode securityNode = securityData;
	    	tempMapCache.put("SecurityMetaData", securityNode);
	    	obj.setCache(tempMapCache);
			
			return obj;

				
	}

	
	public PermissionCacheObject verifyDeleteData( String access_token_user ,
			JsonNode security_metadata_SO_current,
			JsonNode security_metadata_of_the_SU, PermissionCacheObject cache,
			String idmHost, String idmUser, String idmPass,int idmPort) throws PDPServioticyException {
		
		Map<String, Object> internalCache = new HashMap<String, Object>();

		// Check if parameters to connect to IDM exist
	 	 if(idmUser==null || idmPass == null || idmHost ==null || idmPort<0) {
	 		throw new PDPServioticyException(500, "Not enough parameters to talk to the IDM ", "Not enough parameters to talk to IDM");
		 }
		 if(security_metadata_of_the_SU ==null || security_metadata_SO_current ==null)
				throw new PDPServioticyException(500, "No security metadata for the sensor update or service object", "Not enough security metadata for the sensor update or service object");
		 // Connect to IDM if no information is in the cach objecttempMapCache
		 String response = "";
		 if (cache ==null || cache.getCache() == null) {	
			 if(cache==null)
				 cache = new PermissionCacheObject();
		 	 // Check if user is allowed to get data from the SO
			 if(cache.getCache()!=null)
				 internalCache = (Map<String, Object>) cache.getCache();
			 if(((Boolean)internalCache.get("wrong:"+access_token_user)).booleanValue())
			 {
				 cache.setPermission(false);
				 return cache;
			 }
			 IDMCommunicator com = new IDMCommunicator(idmUser, idmPass, idmHost, idmPort);
			 try {
				 response = com.getInformationForUser(access_token_user);
				 if(response ==null)
				 {
					 internalCache.put("wrong:"+access_token_user, new Boolean(true));
					 cache.setPermission(false);
					 return cache;
				 }
				 internalCache.put("wrong:"+access_token_user, new Boolean(false));
			 }
			 catch (PDPServioticyException e){
				 cache.setPermission(false);
				 cache.setCache(e);
				 return cache;
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
			if (userSO != null){
				internalCache.put("UserId", userSO.asText());
			}
			cache.setCache(internalCache);
		 }

		 JsonNode owner = security_metadata_SO_current.findValue("owner_id");
		 if(owner==null)
			 throw new PDPServioticyException(500, "owner not found in service object metadata", "owner_id not found inside security metadata for service object:"+security_metadata_of_the_SU);
		 String soOwner = owner.asText();
		// Check policies
		 if(cache.getUserId().equals(soOwner))
		 {
			 cache.setPermission(true);
		 }
		
		return cache;				
	}
	
	public PermissionCacheObject retrieveSODescription(JsonNode SO, String accessToken,String idmHost, String idmUser, String idmPass,int idmPort)
	{
		//get user access_token, and SO security metadata, cache object
		//set permission boolean in the cache object to true or false depending on permissions
		//return userId in the cache object (internal)
		return genericPublicPrivatePolicy(SO,accessToken,idmHost, idmUser,idmPass, idmPort);
	}
	
	
	public PermissionCacheObject retrieveSOStreams(JsonNode SO, String accessToken,String idmHost, String idmUser, String idmPass,int idmPort)
	{
		return genericPublicPrivatePolicy(SO,accessToken,idmHost, idmUser,idmPass, idmPort);
	}
	
	public PermissionCacheObject updateSODescription(JsonNode SO, String accessToken,String idmHost, String idmUser, String idmPass,int idmPort)
	{
		return checkOwner(SO,accessToken,idmHost, idmUser,idmPass, idmPort);
	}
	
	public PermissionCacheObject deleteSODescription(JsonNode SO, String accessToken,String idmHost, String idmUser, String idmPass,int idmPort)
	{
		return checkOwner(SO,accessToken,idmHost, idmUser,idmPass, idmPort);
	}

	
	public PermissionCacheObject genericPublicPrivatePolicy(JsonNode SO, String accessToken,String idmHost, String idmUser, String idmPass,int idmPort)
	{
		PermissionCacheObject ret = new PermissionCacheObject();
		ret.setPermission(false);
		IdentityVerifier idm = new IdentityVerifier();
		Map<String, Object> tempMapCache = new HashMap<String, Object>();
		String userId = idm.userIdFromToken(accessToken,idmHost, idmUser,idmPass, idmPort);
		tempMapCache.put("UserId", userId);
		if(userId!=null)
		{
		   ret.setPermission(evaluatePolicyGenericPublicPrivate(SO,userId));
		}
		ret.setCache(tempMapCache);
		return ret;
		
	}

	private PermissionCacheObject checkOwner(JsonNode so, String accessToken,String idmHost, String idmUser, String idmPass,int idmPort)
	{
		IdentityVerifier idm = new IdentityVerifier();
		PermissionCacheObject ret = new PermissionCacheObject();
		JsonNode id= so.findValue("id");
		JsonNode owner = so.findValue("owner_id");
		if(id.asText() != null && !id.asText().equals(""))
		{
			Map<String, Object> tempMapCache = new HashMap<String, Object>();
			String uId = idm.userIdFromToken(accessToken,idmHost, idmUser,idmPass, idmPort);
			tempMapCache.put("UserId", uId);
			ret.setCache(tempMapCache);
			//there is a usen authenticated behind the request
			if(uId.equals(owner.asText()))
				ret.setPermission(true);
			else
				ret.setPermission(false);
			return ret;
		}
		return null;
	}

	
	/**
	 * Checks if the private/public policy holds...
	 * @param SO security_metadata_SO (destination SO)
	 * @param userId security_metadata_of_the_SU (input SU)
	 * @return returns true or false depending on the policy evaluation
	 */
	private boolean evaluatePolicyGenericPublicPrivate(JsonNode SO, String userId)
	{
		return evaluatePolicy(SO, userId);
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
				//System.out.println("User SU: " + targetSU.asText() + " " + user);
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








