package de.passau.uni.sec.compose.pdp.servioticy.idm;

import static org.junit.Assert.fail;

import java.io.IOException;
import java.util.UUID;

import org.apache.http.client.methods.CloseableHttpResponse;
import org.apache.http.util.EntityUtils;
import org.junit.After;
import org.junit.Before;
import org.junit.Test;

import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.ObjectMapper;

import de.passau.uni.sec.compose.pdp.servioticy.exception.PDPServioticyException;

public class TestIDMCommunicator 
{
	 private IDMCommunicator com;
	 //replace this for a valid token when running the test
	 private String access_token_user = "token";
	 private String idmHost ="localhost";
	 private String idmProtocol = "http";
	 private int idmPort = 8080;
	 private String idmHTTPDigestUser = "composecontroller";
	 private String idmHTTPDigestPassword = "composecontrollerpassword";
	 @Before
	 public void setUp()
	 {
		  com = new IDMCommunicator(idmHTTPDigestUser, idmHTTPDigestPassword, idmHost, idmPort);
	 }
	 
	 //@Test
	 public void getDataFromUserToken()
	 {
		 
		 try{
			 
			 
			 String response = com.getInformationForUser(access_token_user);
			 System.out.println(response);
		 }
		 catch(PDPServioticyException e)
		 {
			 //TODO handle:
			 fail();
			 System.out.println("User message: "+e.getMessage()+" Status: "+e.getStatus()+" Logging info: "+e.getLogInfo());
		 }

	 }
	 
	 //@Test
	 public void deleteSO() 
	 {
		 try{
			 //add the bearer key word.
			 access_token_user = "Bearer anonymousToken";
			 //"so1meid"
			 String id = "6a0c8d07-4535-4215-8dc7-0a677b63879d";
			 com.deleteSO("http", "localhost", 8080,id ,access_token_user);
			
		 }
		 catch(PDPServioticyException e)
		 {
			 //here code could be 401 or 403, or 404 and there is always a user message...
			 //TODO handle:
			 System.out.println("User message: "+e.getMessage()+" Status: "+e.getStatus()+" Logging info: "+e.getLogInfo());
			 fail();
			 
		 }
	 }
	 
	 //@Test
	 public void createAndDeleteSO()
	 {
		 try{
			 //add the bearer key word.
			 access_token_user = "Bearer "+access_token_user;
			 String random_id = UUID.randomUUID().toString();
			 String JsonBody = "{\"authorization\": \""+access_token_user+"\",\"id\":\""+random_id+"\",\"requires_token\":true, \"data_provenance_collection\":false,\"payment\": true}";
			 CloseableHttpResponse response = com.sendPostToIDM("/idm/serviceobject/",JsonBody);
			 try {
				  
	              System.out.println("----------------------------------------");
	              if(response.getStatusLine().getStatusCode()==401)
	              {
	              	//TODO handle:  here the authentication was wrong
	              	System.err.println("Authentication failed");
	              	fail();
	              }
	              else if(response.getStatusLine().getStatusCode()==403)
	              {
	            	  //TODO handle: the authentication worked... but the access is forbidden
	            	  System.err.println("the authentication worked... but the access is forbidden");
	            	  fail();
	              }
	              else if(response.getStatusLine().getStatusCode()==409)
	              {
	            	  //TODO handle: the SO already exists
	            	 System.err.println("Service object already exists");
	            	 fail();
	              }
	              else if (response.getStatusLine().getStatusCode() == 500)
	              {
	            	  //TODO handle: Identity management is having internal problems!
	            	  System.err.println("Identity management is having internal problems!");
	            	  fail();
	              }
	              else if (response.getStatusLine().getStatusCode()==201) //This means is created!
	              {
	            	  
	                System.out.println(response.getStatusLine());
	                System.out.println("----------------------------------------");
	                String r = EntityUtils.toString(response.getEntity());
	                System.out.println(r);
	                JsonNode json = new ObjectMapper().readTree(r);
	                JsonNode id = json.get("id");
	                System.out.println("foun id:"+id.asText());
	                com.deleteSO(idmProtocol, idmHost, idmPort,id.asText() ,access_token_user);
	                
	                //remember to call clear at the end on com object, to close the Apache HTTP client
	               }
	              
				
				} catch (IOException e) {
					//TODO handle:  this means ->  an http protocol error
					e.printStackTrace();
					fail();
				
				}
				finally {
					
	                try {
						((CloseableHttpResponse) response).close();
					} catch (IOException e) {
						//log debug information. Doesn't seem to be a big deal
						fail();
						e.printStackTrace();
					}
	          }
		 }
		 catch(PDPServioticyException e)
		 {
			 System.out.println("User message: "+e.getMessage()+" Status: "+e.getStatus()+" Logging info: "+e.getLogInfo());
			 e.printStackTrace();
			 //TODO handle:
			 fail();
		 }
	 }
	 //@Test
	 public void getSODataIncludingAPIToken()  
	 {
		
		 try{
			 CloseableHttpResponse response = com.sendGetToIDM("/idm/serviceobject/api_token_data/so1meid");
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
	              
				
				} catch (IOException e) {
					//TODO handle:  this means ->  an http protocol error
					fail();
					e.printStackTrace();
				}
				finally {
					
	                try {
						((CloseableHttpResponse) response).close();
					} catch (IOException e) {
						//log debug information. Doesn't seem to be a big deal
						fail();
						e.printStackTrace();
					}
	          }
		 }
		 catch(PDPServioticyException e)
		 {
			 System.out.println("User message: "+e.getMessage()+" Status: "+e.getStatus()+" Logging info: "+e.getLogInfo());
		 }     		
	 }
	 
	 //@Test
	 public void testGetUserInfoById() throws PDPServioticyException
	 {
		 String id  = "746a13fd-8dc1-4aeb-afae-ebf5d7720056";
		 String res = this.com.getInformationForUserById(null, id);
		 System.out.println("result: "+res);
		 
		 res = this.com.getInformationforAnyId(null, id);
		 System.out.println("result: "+res);
	 }
	 @After
	 public void cleanUp()
	 {
		 com.clear();
	 }
}
