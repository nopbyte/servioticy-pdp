package de.passau.uni.sec.compose.pdp.servioticy.idm;

import static org.junit.Assert.fail;

import java.io.IOException;
import java.util.UUID;

import org.apache.http.HttpResponse;
import org.apache.http.client.ClientProtocolException;
import org.apache.http.client.methods.CloseableHttpResponse;
import org.apache.http.util.EntityUtils;
import org.junit.After;
import org.junit.Before;
import org.junit.Test;

import de.passau.uni.sec.compose.pdp.servioticy.exception.PDPServioticyException;

public class TestIDMCommunicator 
{
	 private IDMCommunicator com;
	 @Before
	 public void setUp()
	 {
		  com = new IDMCommunicator("composecontroller", "composecontrollerpassword", "localhost", 8080);
	 }
	 
	 
	 @Test
	 public void createSO()
	 {
		 try{
			 //replace this for a valid token when running the test
			 String access_token_user = "eyJhbGciOiJSUzI1NiJ9.eyJqdGkiOiI3ZGQ0MTM2OS0zZjNjLTRmYTMtYWFhYy1lMzJlMTc4MmNlZjYiLCJzdWIiOiJjMzI4ZjliNi1iYzA4LTRmYWQtOGNiNi04YmVkZjlmNzk5OGUiLCJzY29wZSI6WyJzY2ltLnVzZXJpZHMiLCJwYXNzd29yZC53cml0ZSIsImNsb3VkX2NvbnRyb2xsZXIud3JpdGUiLCJvcGVuaWQiLCJjbG91ZF9jb250cm9sbGVyLnJlYWQiXSwiY2xpZW50X2lkIjoidm1jIiwiY2lkIjoidm1jIiwidXNlcl9pZCI6ImMzMjhmOWI2LWJjMDgtNGZhZC04Y2I2LThiZWRmOWY3OTk4ZSIsInVzZXJfbmFtZSI6InRlc3QyIiwiZW1haWwiOiJ0ZXN0MkBjb21wb3NlLmNvbSIsImlhdCI6MTQwMzQyNjU3MCwiZXhwIjoxNDAzNDY5NzcwLCJpc3MiOiJodHRwOi8vbG9jYWxob3N0OjgwODAvdWFhL29hdXRoL3Rva2VuIiwiYXVkIjpbInNjaW0iLCJvcGVuaWQiLCJjbG91ZF9jb250cm9sbGVyIiwicGFzc3dvcmQiXX0.DLYyQSeLwrsVH-0GeWAA9MFbL3Bqzbf-RUXYXk5QY6DROuky_lnBCNfZdpvpIcO7VkR9TR4PcPyzuf6gUxceQ6jp8u2FNrp6icyp0Ff3hm2h3JO4QRnkn2Ir7HfYX7kKVV-28ZykgOru7NT-VQWJfoGYqk2tOCqUqMLvVVMXfjmBkVkjg-_LRppbqfWoIjU3XDqwfPefF5UWvhmXKkPAe2TLj_RgtarmrCOT_KiCNkIoJUc4M5tBxak48WVahgrZXeqKjbprnwXMuVfQDyZSaCF9bc7u0sUFULuqxXBNQd3gT-9HkafYdPwR2Ym1aAs_QUXEpRMYgQoowzQu26aUTA";
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
			 //TODO handle:
			 fail();
			 System.out.println("User message: "+e.getMessage()+" Status: "+e.getStatus()+" Logging info: "+e.getLogInfo());
		 }
	 }
	 @Test
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
	 @After
	 public void cleanUp()
	 {
		 com.clear();
	 }
}
