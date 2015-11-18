package de.passau.uni.sec.compose.pdp.servioticy.authz;




import iotp.model.storage.model.EncodedUser;

import java.io.IOException;
import java.util.HashMap;
import java.util.List;
import java.util.Map;
import java.lang.String;

import org.apache.http.client.methods.CloseableHttpResponse;
import org.apache.http.util.EntityUtils;
import org.w3c.dom.UserDataHandler;

import com.fasterxml.jackson.core.JsonProcessingException;
import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.ObjectMapper;
import com.fasterxml.jackson.databind.ObjectWriter;
import com.fasterxml.jackson.databind.node.ObjectNode;

import de.passau.uni.sec.compose.pdp.servioticy.PermissionCacheObject;
import de.passau.uni.sec.compose.pdp.servioticy.exception.PDPServioticyException;
import de.passau.uni.sec.compose.pdp.servioticy.idm.IDMCommunicator;
import de.passau.uni.sec.compose.pdp.servioticy.idm.IdentityVerifier;
import de.passau.uni.sec.compose.pdp.servioticy.policy.PolicyEvaluation;

public class AuthorizationServioticy 
{
	private static final String IDM_USER_SECTION = "id";
	private PolicyEvaluation pdp;

	
	/**
	 * Constructor
	 */
	public AuthorizationServioticy(PolicyEvaluation p){
		pdp = p;
	}
	
	
	
	/**
	 * Verifies the policy for the current SO and a SU
	 *
	 * @param security_metadata_SO_current
	 * @param security_metadata_of_the_SU
	 * @param cache
	 * @param idmHost
	 * @param idmUser
	 * @param idmPass
	 * @param idmPort
	 * @return returns true or false in the "Permission" entry of the cache object depending on the policy evaluation
	 */
	public PermissionCacheObject verifyGetData( String access_token_user ,
			JsonNode security_metadata_SO_current,
			JsonNode security_metadata_of_the_SU, PermissionCacheObject cache,
			String idmHost, String idmUser, String idmPass,int idmPort) throws PDPServioticyException {
		
		Map<String, Object> internalCache = new HashMap<String, Object>();
		JsonNode userInfo;
		String userId;

		// Check if parameters to connect to IDM exist
	 	 if(idmUser==null || idmPass == null || idmHost == null || idmPort<0) {
	 		throw new PDPServioticyException(500, "Not enough parameters to talk to the IDM ", "Not enough parameters to talk to IDM");
		 }
		 if(security_metadata_of_the_SU ==null || security_metadata_SO_current ==null)
				throw new PDPServioticyException(500, "No security metadata for the sensor update or service object", "Not enough security metadata for the sensor update or service object");
		 // Connect to IDM if no information is in the cache objecttempMapCache
		 String response = "";
		 if (cache == null || cache.getCache() == null || cache.getUserId() == null || cache.getUserInfo() == null) {	
			 userInfo =  getUserInfoIDM(idmUser, idmPass, idmHost, idmPort, access_token_user);
			 if (userInfo == null){
			 		throw new PDPServioticyException(500, "Could not get User info from IDM ", "Could not get User info from IDM");
			 }
			 userId = userInfo.findValue(IDM_USER_SECTION).toString();
			 cache.setUserInfo(userInfo);
			 cache.setUserId(userId);
		 }
		 else{
			 userInfo = cache.getUserInfo();
			 userId = cache.getUserId();
		 }
		 // TODO wrong access token handling see below
		 /*if(internalCache.containsKey("wrong:"+access_token_user)&&((Boolean)internalCache.get("wrong:"+access_token_user)).booleanValue())
		 {
			 cache.setPermission(false);
			 cache.setCache(internalCache);
			 return cache;
		 }*/
		 //TODO check if owner/SO can be removed
		 /*JsonNode owner = security_metadata_SO_current.findValue("owner_id");
		 if(owner==null)
		 {
			 throw new PDPServioticyException(500, "owner not found in service object metadata", "owner_id not found inside security metadata for service object:"+security_metadata_of_the_SU);
		 }
		 String soOwner = owner.asText();*/
		 //boolean poleval = evaluatePolicy(security_metadata_of_the_SU, cache.getUserId()); // Dummy
		 
		 
		 boolean poleval = pdp.checkAccess(security_metadata_of_the_SU, cache.getUserId(), userInfo);
		 cache.setPermission(poleval);
		 cache.setCache(internalCache);
		
		return cache;		
	}

	/**
	 * Checks the policy during dispatching 
	 *
	 * @param security_metadata_SO (destination SO)
	 * @param security_metadata_of_the_SU (input SU)
	 * @param idmHost
	 * @param idmUser)&&
	 * @param idmPass
	 * @param idmPort
	 * @return returns true or false in the "Permission" entry of the cache object depending on the policy evaluation
	 */
	public PermissionCacheObject verifyGetDataDispatch(
			JsonNode security_metadata_SO_destination,
			JsonNode security_metadata_of_the_SU,
			String idmHost, String idmUser, String idmPass,int idmPort, PermissionCacheObject cache) throws PDPServioticyException {

			String stream = null;
			if (cache != null){
				stream = cache.getStream();
			}
		
	 		PermissionCacheObject obj = new PermissionCacheObject();
 			if (security_metadata_SO_destination == null || security_metadata_of_the_SU == null)
 			{
				obj.setPermission(false);
				return obj;

 			}

			// Add check if it is the same SO if yes return true. 
			// http://docs.servioticysecurity.apiary.io/

			//boolean evaluation = evaluatePolicy(security_metadata_SO_destination, security_metadata_of_the_SU); // Dummy
 			boolean evaluation = pdp.checkFlow(security_metadata_SO_destination, security_metadata_of_the_SU, stream);
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
			 
			 IDMCommunicator com = new IDMCommunicator(idmUser, idmPass, idmHost, idmPort);
			 try {
				 response = com.getInformationForUser(access_token_user);
				 if(response ==null)
				 {
					 internalCache.put("wrong:"+access_token_user, new Boolean(true));
					 cache.setPermission(false);
					 cache.setCache(internalCache);
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
		 else
		 {
			 internalCache = (Map<String, Object>) cache.getCache();
		 }
		 if(internalCache.containsKey("wrong:"+access_token_user)&&((Boolean)internalCache.get("wrong:"+access_token_user)).booleanValue())
		 {
			 cache.setPermission(false);
			 cache.setCache(internalCache);
			 return cache;
		 }
		 JsonNode owner = security_metadata_SO_current.findValue("owner_id");
		 if(owner==null)
			 throw new PDPServioticyException(500, "owner not found in service object metadata", "owner_id not found inside security metadata for service object:"+security_metadata_of_the_SU);
		 String soOwner = owner.asText();
		// Check policies
		 if(cache.getUserId().equals(soOwner))
		 {
			 cache.setPermission(true);
			 cache.setCache(internalCache);
		 }
		cache.setCache(internalCache);
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

	/*
	 * Checks read access
	 */
	public PermissionCacheObject genericPublicPrivatePolicy(JsonNode SO, String accessToken,String idmHost, String idmUser, String idmPass,int idmPort)
	{
		PermissionCacheObject ret = new PermissionCacheObject();
		ret.setPermission(false);
		IdentityVerifier idm = new IdentityVerifier();
		Map<String, Object> tempMapCache = new HashMap<String, Object>();
		//String userId = idm.userIdFromToken(accessToken,idmHost, idmUser,idmPass, idmPort);
		JsonNode userInfo;
		String userId;
		try {
			userInfo = getUserInfoIDM(idmUser, idmPass, idmHost, idmPort, accessToken);
			userId = userInfo.findValue(IDM_USER_SECTION).toString();
		} catch (PDPServioticyException e) {
			userInfo = null;
			ret.setPermission(false);
			return ret;
		}

		if(userId != null && userInfo != null)
		{
		   ret.setPermission(evaluatePolicyGenericPublicPrivate(SO,userId, userInfo));
		   ret.setUserInfo(userInfo);
		   ret.setUserId(userId);
		}
		return ret;
	}

	
	/*
	 * Checks write access
	 */
	public PermissionCacheObject genericPublicPrivatePolicyWrite(JsonNode SO, String accessToken,String idmHost, String idmUser, String idmPass,int idmPort)
	{
		PermissionCacheObject ret = new PermissionCacheObject();
		ret.setPermission(false);
		IdentityVerifier idm = new IdentityVerifier();
		Map<String, Object> tempMapCache = new HashMap<String, Object>();
		//String userId = idm.userIdFromToken(accessToken,idmHost, idmUser,idmPass, idmPort);
		JsonNode userInfo;
		String userId;
		try {
			userInfo = getUserInfoIDM(idmUser, idmPass, idmHost, idmPort, accessToken);
			userId = userInfo.findValue(IDM_USER_SECTION).toString();
		} catch (PDPServioticyException e) {
			userInfo = null;
			ret.setPermission(false);
			return ret;
		}

		if(userId != null && userInfo != null)
		{
		   ret.setPermission(evaluatePolicyGenericPublicPrivateWrite(SO,userId, userInfo));
		   ret.setUserInfo(userInfo);
		   ret.setUserId(userId);
		}
		return ret;
	}
	
	
	public PermissionCacheObject genericPublicPrivatePolicyNoIDM(JsonNode SU, PermissionCacheObject cache)
	{
		PermissionCacheObject ret = new PermissionCacheObject();
		ret.setPermission(false);
		// Get user id
		String userId = "";
		userId = cache.getUserId();
		JsonNode userInfo = cache.getUserInfo();
		// Evaluate policy
		if(userId!=null && userInfo != null)
		{
		   ret.setPermission(evaluatePolicyGenericPublicPrivate(SU,userId, userInfo));
		}
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
			//there is a user authenticated behind the request
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
	private boolean evaluatePolicyGenericPublicPrivate(JsonNode SO, String userId, JsonNode userInfo)
	{
		//return evaluatePolicy(SO, userId); // Dummy
		return pdp.checkAccess(SO, userId, userInfo);
				
	}
	
	/**
	 * Checks if the private/public policy holds...
	 * @param SO security_metadata_SO (destination SO)
	 * @param userId security_metadata_of_the_SU (input SU)
	 * @return returns true or false depending on the policy evaluation
	 */
	private boolean evaluatePolicyGenericPublicPrivateWrite(JsonNode SO, String userId, JsonNode userInfo)
	{
		//return evaluatePolicy(SO, userId); // Dummy
		return pdp.checkWriteAccess(SO, userId, userInfo, null);
				
	}
	
	/**
	 * Checks if the private/public policy holds...
	 * @param SO security_metadata_SO (destination SO)
	 * @param userId security_metadata_of_the_SU (input SU)
	 * @return returns true or false depending on the policy evaluation
	 */
	private boolean evaluatePolicyGenericPublicPrivateWrite(JsonNode SO, String userId, JsonNode userInfo, String stream)
	{
		//return evaluatePolicy(SO, userId); // Dummy
		return pdp.checkWriteAccess(SO, userId, userInfo, stream);
				
	}
	
	/**
	 * Checks the policy during dispatching 
	 *
	 * @param security_metadata_SO (destination SO)
	 * @param security_metadata_of_the_SU (input SU)
	 * @return returns true or false depending on the policy evaluation
	 */
	private boolean evaluatePolicyDummy(JsonNode SO, JsonNode inputSU){
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
		List<JsonNode> flowsSU = inputSU.findValues("flows");
		if (flowsSU.isEmpty() == true) {flowsSU = inputSU.findValues("policy");}
		for (JsonNode currentFlow : flowsSU)
		{
			// Get target
			JsonNode targetSU = currentFlow.findValue("target");
			// Get type and id of the target
			JsonNode typeSU = targetSU.get("type");
			JsonNode idSU = targetSU.get("id");
			
			if (targetSU == null) {continue;}
			// Evaluate policy of SU
			JsonNode targetFlowSU = policySU;
			
			if (typeSU != null && typeSU.asText().equals("user") && idSU != null && idSU.asText().equals(userSO.asText()))
			{
				ret = true;
			}
			else if (typeSU != null && typeSU.asText().equals("any") && idSU == null)
			{
					ret = true;
			}
		}
		if (ret == false){return false;};
		// Interate over the flows for the destination policies (SO)
		List<JsonNode> flowsSO = SO.findValues("flows");
		for (JsonNode currentFlow : flowsSO)
		{
			// Get source
			JsonNode sourceSO = currentFlow.findValue("source");
			// Get type and id of the target
			JsonNode typeSO = sourceSO.get("type");
			JsonNode idSO = sourceSO.get("id");
			if (sourceSO == null) {continue;} //.isValueNode() 
			// Evaluate policy of SU
			JsonNode sourceFlowSO = policySO;
			if (typeSO != null && typeSO.asText().equals("user") && idSO != null && idSO.asText().equals(userSU.asText()))
			{
				ret = true;
			}
			else if (typeSO != null && typeSO.asText().equals("any") && idSO == null)
			{
				ret = true;
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
	private boolean evaluatePolicyDummy(JsonNode SU, String user){
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
		List<JsonNode> flowsSU = SU.findValues("flows");
		if (flowsSU.isEmpty() == true) {flowsSU = SU.findValues("policy");}
		for (JsonNode currentFlow : flowsSU)
		{
			// Get target
			JsonNode targetSU = currentFlow.findValue("target");
			if (targetSU == null) {continue;}
			// Evaluate policy of SU
			JsonNode targetFlowSU = policySU;
			// Get type and id of the target
			JsonNode typeSU = targetSU.get("type");
			JsonNode idSU = targetSU.get("id");

			if (typeSU.asText().equals("any") && idSU == null)
			{
				return true;
			}
			else if (typeSU.asText().equals("user") && idSU.asText().equals(user))
			{
				return true; 
			}
		}
		return ret;
	}

	

	/**
	 * Checks if a the  
	 *
	 * @param security_metadata_SU 
	 * @param user that wants to access the SU
	 * @return returns true or false depending on the policy evaluation
	 */
	public PermissionCacheObject getThisSubscriptionInfoForStream(String token, String idmHost, String idmUser, String idmPass,int idmPort, PermissionCacheObject cache) {
		PermissionCacheObject ret = new PermissionCacheObject();
		ret.setPermission(false);
		
		// Get subscription info
		String subInfo = cache.getSubscriptionInfo();
		// Parse info
		ObjectMapper mapperUser = new ObjectMapper();
		JsonNode subInfoJSON = null;
		try {
			subInfoJSON = mapperUser.readTree(subInfo);
		} catch (JsonProcessingException e1) {
			System.out.println("Could not parse the info of the subscription.");
			return ret;
		} catch (IOException e1) {
			System.out.println("Could not parse the info of the subscription.");
			return ret;
		}
		// Find the owner of the subscription
		JsonNode userId = subInfoJSON.findValue("userId");
		if (userId == null)
		{
			System.out.println("Could not find the userId in the subscription info.");
			return ret;
		}
		// Get user-id from authToken from idm or out of the cache object
		String owner = "";
		if (cache.getUserId() != null) {
			owner = cache.getUserId();
		} else {
			IdentityVerifier idm = new IdentityVerifier();
			owner = idm.userIdFromToken(token,idmHost, idmUser,idmPass, idmPort);
		}
		if (owner != null && owner != "") {
			ret.setUserId(owner);
		}
		// Check if user is owner
		System.out.println("Owner: " + owner + " usederID: " + userId.asText());
		if (owner.equals(userId.asText())) {
			ret.setPermission(true);
		} 


		return ret;
	}

	/**
	 * This method gets the user information from user, and the normal parameters 
	 * @param user
	 * @param security_metadata_SO_current
	 * @param cache 
	 * @param stream
	 */
	public boolean evaluatePolicy(EncodedUser user, JsonNode security_metadata_SO_current,
		String stream) throws PDPServioticyException{
		boolean ret = false;
		String jsonUser = "";
		// EncodedUser to JsonNode
		ObjectWriter ow = new ObjectMapper().writer().withDefaultPrettyPrinter();
		try {
			jsonUser = ow.writeValueAsString(user);
		} catch (JsonProcessingException e) {
			System.out.println("PDP Error during parsing of the EncodedUser: " + e);
			return false;
		}
		System.out.println("JSON of encoded user: " + jsonUser);
	    ObjectMapper mapper = new ObjectMapper();
	    JsonNode user_data = null;
	    try {
			user_data = mapper.readTree(jsonUser);
		} catch (JsonProcessingException e) {
			System.out.println("PDP Error during parsing of the EncodedUser to JsonNode: " + e);
			return false;
		} catch (IOException e) {
			System.out.println("PDP Error during parsing of the EncodedUser to JsonNode: " + e);
			return false;
		}
	    
		ret = pdp.checkWriteAccess(security_metadata_SO_current, user.getId(), user_data, stream);
		return ret;
	}

	/*
	 * Get IDM info with token
	 */
	private JsonNode getUserInfoIDM(String idmUser, String idmPass, String idmHost, int idmPort, String access_token_user) throws PDPServioticyException{
		JsonNode ret = null;
		if(idmUser==null || idmPass == null || idmHost ==null || idmPort<0) {
	 		throw new PDPServioticyException(500, "Not enough parameters to talk to the IDM ", "Not enough parameters to talk to IDM");
		 }
		 // Connect to IDM if no information is in the cache objecttempMapCache
		 String response = "";
	 	 // Check if user is allowed to get data from the SO
		 IDMCommunicator com = new IDMCommunicator(idmUser, idmPass, idmHost, idmPort);
		 try {
			 response = com.getInformationForUser(access_token_user);
			 if(response ==null){
				 //internalCache.put("wrong:"+access_token_user, new Boolean(true));
				 return null;
			 }
			 //internalCache.put("wrong:"+access_token_user, new Boolean(false));
		 }
		 catch (PDPServioticyException e){
			 return null;
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
		ret = user_data;
		//JsonNode userSO = user_data.findValue(IDM_USER_SECTION);
		return ret;
	}
}








