package de.passau.uni.sec.compose.pdp.servioticy.authz;




import java.io.IOException;

import org.apache.http.client.methods.CloseableHttpResponse;
import org.apache.http.util.EntityUtils;

import com.fasterxml.jackson.databind.JsonNode;

import de.passau.uni.sec.compose.pdp.servioticy.PermissionCacheObject;
import de.passau.uni.sec.compose.pdp.servioticy.exception.PDPServioticyException;
import de.passau.uni.sec.compose.pdp.servioticy.idm.IDMCommunicator;

public class AuthorizationServioticy 
{
	public PermissionCacheObject verifyGetData( String access_token_user ,
			JsonNode security_metadata_SO_current,
			JsonNode security_metadata_of_the_SU, PermissionCacheObject cache,
			String idmHost, String idmUser, String idmPass,int idmPort) throws PDPServioticyException {
		
	 	 PermissionCacheObject obj = null;
	 	 IDMCommunicator com = new IDMCommunicator(idmUser, idmPass, idmHost, idmPort);
	 	 if(idmUser==null || idmPass == null || idmHost ==null || idmPort<0)
	 		throw new PDPServioticyException(500, "Not enough parameters to talk to the IDM ", "Not enough parameters to talk to IDM");
			
	 	 
	 	
			 CloseableHttpResponse response = com.sendGetToIDM("/idm/serviceobject/api_token_data/140602741741204bab8aeda86472fbfab310445341516");
			 try {
				  
	              System.out.println("----------------------------------------");
	              if(response.getStatusLine().getStatusCode()==401)
	              {
	              	//TODO handle:  here the authentication was wrong
	              	System.err.println("Authentication failed");
	              }
	              else if(response.getStatusLine().getStatusCode()==403)
	              {
	            	  //TODO handle: the authentication worked... but the access is forbidden
	              }
	              else if(response.getStatusLine().getStatusCode()==404)
	              {
	            	  //TODO handle: the SO doesn't exist
	              }
	              else if (response.getStatusLine().getStatusCode() == 500)
	              {
	            	  //TODO handle: Identity management is having internal problems!
	              }
	              else if (response.getStatusLine().getStatusCode()==200)
	              {
	            	  
	                System.out.println(response.getStatusLine());
	                System.out.println("----------------------------------------");
	                System.out.println(EntityUtils.toString(response.getEntity()));
	                //remember to call clear at the end on com object, to close the Apache HTTP client
	               }
	               //ObjectMapper mapper = new ObjectMapper();
	               //JsonNode node = mapper.readTree(content)
	               Object policies = security_metadata_SO_current.get("policy");
	               if(cache == null)
            	   {
            		   cache = new PermissionCacheObject();
            	   }
	               if(policies != null)
	                 cache.setPermission(false);
            	  else 
	                 cache.setPermission(true);
	               return cache;
	              				
				} catch (IOException e) {
					throw new PDPServioticyException(500, "there is an HTTP protocol problem when calling COMPOSE IDM", "there is an HTTP protocol problem ");
				    
				}
				
	}
}
