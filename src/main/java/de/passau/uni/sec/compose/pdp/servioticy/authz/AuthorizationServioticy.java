package de.passau.uni.sec.compose.pdp.servioticy.authz;




import java.io.IOException;

import org.apache.http.client.methods.CloseableHttpResponse;
import org.apache.http.util.EntityUtils;

import com.fasterxml.jackson.core.JsonProcessingException;
import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.ObjectMapper;

import de.passau.uni.sec.compose.pdp.servioticy.PermissionCacheObject;
import de.passau.uni.sec.compose.pdp.servioticy.exception.PDPServioticyException;
import de.passau.uni.sec.compose.pdp.servioticy.idm.IDMCommunicator;

import java.util.LinkedList;
import java.util.List;
import com.jayway.jsonpath.Criteria;
import com.jayway.jsonpath.Filter;
import com.jayway.jsonpath.JsonPath;

public class AuthorizationServioticy 
{
	private static final String DEFAULT_PRIVATE_POLICY = "\"private\"";
	private static final String DEFAULT_PUBLIC_POLICY = "\"public\"";
	
	private static final String IDM_USER_SECTION = "username";
	private static final String SO_USER_SECTION = "owner_id";
	private static final String PROVENANCE_USER_SECTION = "onbehalf_of";

	

	

	
	public PermissionCacheObject verifyGetData( String access_token_user ,
			JsonNode security_metadata_SO_current,
			JsonNode security_metadata_of_the_SU, PermissionCacheObject cache,
			String idmHost, String idmUser, String idmPass,int idmPort) throws PDPServioticyException {
		
	 	 PermissionCacheObject obj = null;
	 	 IDMCommunicator com = new IDMCommunicator(idmUser, idmPass, idmHost, idmPort);
	 	 if(idmUser==null || idmPass == null || idmHost ==null || idmPort<0)
	 		throw new PDPServioticyException(500, "Not enough parameters to talk to the IDM ", "Not enough parameters to talk to IDM");
			
	 	 	// Check if user is allowed to get data from the SO
	 	
			 //CloseableHttpResponse response = com.sendGetToIDM("/idm/serviceobject/api_token_data/140602741741204bab8aeda86472fbfab310445341516");
			 String response = null;
			 try {
				 response = com.getInformationForUser(access_token_user);
			 }
			 catch (PDPServioticyException e){
				 obj.setPermission(false);
				 obj.setCache(e);
				 return obj;
			 }
			 
			 // Check if response is correct (including exceptions		 
	 	 	 // Build a JsonNode
	 	    ObjectMapper mapperUser = new ObjectMapper();
		    JsonNode user_data = null;
			try {
				user_data = mapperUser.readTree(response);
			} catch (JsonProcessingException e1) {
				user_data = null;
			} catch (IOException e1) {
				user_data = null;
			}
				

			 // Check policies
			JsonNode userSO = security_metadata_SO_current.findValue(IDM_USER_SECTION);
			checkPolicy(security_metadata_SO_current, userSO, user_data);
			obj.setPermission(checkPolicy(security_metadata_SO_current, userSO, user_data));
			 return obj;
				
	}
	
	
	public PermissionCacheObject verifyGetDataDispatch(
			JsonNode security_metadata_SO_destination,
			JsonNode security_metadata_of_the_SU,
			String idmHost, String idmUser, String idmPass,int idmPort) throws PDPServioticyException {

			// http://docs.servioticysecurity.apiary.io/
		
		
 			PermissionCacheObject obj = new PermissionCacheObject();		

 			// Check if SO or SU is null
 			if (security_metadata_SO_destination == null || security_metadata_of_the_SU == null)
 			{
				obj.setPermission(false);
				return obj;

 			}
 			
			// ---------------------------
			// Dummy policy check
			// ---------------------------	
 			
			// Get Policy and user-id's
			JsonNode policySO = security_metadata_SO_destination.findValue("policy");
			JsonNode userSO = security_metadata_SO_destination.findValue(SO_USER_SECTION);
			JsonNode provenance = security_metadata_of_the_SU.findValue("provenance");
			JsonNode userSU = null;
			if (provenance != null){				
				userSU = provenance.findValue(PROVENANCE_USER_SECTION);
			}
			// Check policies
			obj.setPermission( checkPolicy(policySO, userSO, userSU));
			if (obj.isPermission() == true)
			{
				JsonNode policySU = security_metadata_of_the_SU.findValue("policy");

				obj.setPermission(checkPolicy(policySU, userSU, userSO));
			}

			return obj;				
	}


//------------------------------------------------------------

	// Obsolete
	public String getJsonValue(String Json, String Entry) 
	{	
		String returnString = "";
		List<Object>  tempList = new LinkedList<Object>();
		try{
			tempList = JsonPath.read(Json, "." + Entry);
		} catch (Exception e) {
			return "";
		}

		for (Object tempObject : tempList)
		{
			if (tempObject != null)
			{
				returnString += tempObject.toString();
			}
		}	
		return returnString;
	}
	
	 /**
	  * Function to evaluate the default polices
	  * 
	  * @param policy of entity owned by A
	  * @param user A 
	  * @param userty B that want to access entity of A
	  * @return True if B is allowed to access A
	  */
	private boolean checkPolicy(JsonNode policy, JsonNode entityOfPolicy, JsonNode entityWhantAccess)
	{
		if(policy != null)
		{
			if (policy.toString().equals(DEFAULT_PUBLIC_POLICY))
			{
				return true;
			}
			else if (policy.toString().equals(DEFAULT_PRIVATE_POLICY)){
				// Check if it the same user
				if (entityOfPolicy != null && entityWhantAccess != null)
				{
					if (entityOfPolicy.toString().equals(entityWhantAccess.toString()) == true){
						return true;
					}					
					return false;
				}
			}
			else {
				System.out.println("Unknown policy: " + policy);
			}
		}
		else {
			System.out.println("No policy in SO or SU");
			return false;
		}
		return false;
	}


}


















