package de.passau.uni.sec.compose.pdp.servioticy.idm;



import java.io.IOException;
import java.net.URI;
import java.util.HashMap;
import java.util.LinkedHashMap;
import java.util.Map;

import org.apache.http.HttpHost;
import org.apache.http.ParseException;
import org.apache.http.auth.AuthScope;
import org.apache.http.auth.UsernamePasswordCredentials;
import org.apache.http.client.AuthCache;
import org.apache.http.client.ClientProtocolException;
import org.apache.http.client.CredentialsProvider;
import org.apache.http.client.methods.CloseableHttpResponse;
import org.apache.http.client.methods.HttpGet;
import org.apache.http.client.methods.HttpPost;
import org.apache.http.client.methods.HttpUriRequest;
import org.apache.http.client.protocol.HttpClientContext;
import org.apache.http.entity.StringEntity;
import org.apache.http.impl.auth.DigestScheme;
import org.apache.http.impl.client.BasicAuthCache;
import org.apache.http.impl.client.BasicCredentialsProvider;
import org.apache.http.impl.client.CloseableHttpClient;
import org.apache.http.impl.client.DefaultHttpClient;
import org.apache.http.impl.client.HttpClients;
import org.apache.http.util.EntityUtils;
import org.springframework.http.HttpEntity;
import org.springframework.http.HttpHeaders;
import org.springframework.http.HttpMethod;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.web.client.HttpClientErrorException;
import org.springframework.web.client.RestTemplate;

import de.passau.uni.sec.compose.pdp.servioticy.exception.PDPServioticyException;
import de.passau.uni.sec.compose.pdp.servioticy.idm.spring.util.DigestHttpComponentsClientHttpRequestFactory;
import de.passau.uni.sec.compose.pdp.servioticy.idm.spring.util.HttpEntityEnclosingDeleteRequest;

/**
 * This class encapsulates the communication with the Identity Management
 * @author dp
 *
 */
public class IDMCommunicator {

	/**
	 * Apache client used to communicate with IDM
	 */
	private CloseableHttpClient httpclient;
	/**
	 * Target used to send data to IDM
	 */
	private HttpHost target;
	
	public static RestTemplate digestRestTemplate() {
        DefaultHttpClient client = new DefaultHttpClient();

        UsernamePasswordCredentials credentials = new UsernamePasswordCredentials(
                "composecontroller", "composecontrollerpassword");

        client.getCredentialsProvider().setCredentials(
                new AuthScope("localhost", 8080, AuthScope.ANY_REALM),
                credentials);

        RestTemplate digestRestTemplate = new RestTemplate();
        digestRestTemplate
                .setRequestFactory(new DigestHttpComponentsClientHttpRequestFactory(
                        client) {
                    @Override
                    protected HttpUriRequest createHttpUriRequest(
                            HttpMethod httpMethod, URI uri) {
                        if (HttpMethod.DELETE == httpMethod) {
                            return new HttpEntityEnclosingDeleteRequest(uri);
                        }
                        return super.createHttpUriRequest(httpMethod, uri);
                    }
                });
        return digestRestTemplate;
    }
	
	private CloseableHttpResponse internalGetToIDM(String uri, Map<String,String> headers ) throws PDPServioticyException
	{
		
	        // Create AuthCache instance
            AuthCache authCache = new BasicAuthCache();
            
            // Generate DIGEST scheme object, initialize it and add it to the local
            DigestScheme digestAuth = new DigestScheme();
            digestAuth.overrideParamter("realm", "Digest realm for COMPOSE IDM");
            digestAuth.overrideParamter("nonce", DigestScheme.createCnonce());
            authCache.put(target, digestAuth);

            // Add AuthCache to the execution context
            HttpClientContext localContext = HttpClientContext.create();
            localContext.setAuthCache(authCache);

            HttpGet httpget = new HttpGet(uri);
            
            if(headers !=null)
            {
            	for(String key: headers.keySet())
            	{
            		httpget.setHeader(key, headers.get(key));
            		System.out.println("setting header"+key+":"+headers.get(key));
            	}
            }
            
            CloseableHttpResponse response  = null;
        	try {
				response = httpclient.execute(target, httpget, localContext);
				//System.out.println(EntityUtils.toString(response.getEntity()));
				return response;
			
        	} catch (ClientProtocolException e) {
				throw new PDPServioticyException(500, "A problem with the connection occurred, or the connection was aborted when calling COMPOSE IDM", "there is a problem with the network connection");
		    
			} catch (IOException e) {
				throw new PDPServioticyException(500, "there is an HTTP protocol problem when calling COMPOSE IDM", "there is an HTTP protocol problem ");
			    
			}
	}
	
	public IDMCommunicator(String username, String password, String host, int port)
	{
		this.target = new HttpHost(host, port, "http");        
        CredentialsProvider credsProvider = new BasicCredentialsProvider();
        credsProvider.setCredentials(
                new AuthScope(target.getHostName(), target.getPort()),
                new UsernamePasswordCredentials(username, password));
        
		 this.httpclient = HttpClients.custom()
	                .setDefaultCredentialsProvider(credsProvider)
	                .build();
	       
	}
	
	public void clear()
	{
		try {
			httpclient.close();
			
		} catch (IOException e) {
			//TODO integrate with BSC... log debug information. Doesn't seem to be a big deal... this might end up not closing connections?
		}	
	}
	
	public CloseableHttpResponse sendGetToIDM(String uri) throws PDPServioticyException
	{
		return internalGetToIDM(uri, null);
	}
	
	public CloseableHttpResponse sendPostToIDM(String uri,String JsonAsString) throws PDPServioticyException
	{
			        // Create AuthCache instance
            AuthCache authCache = new BasicAuthCache();
            
            // Generate DIGEST scheme object, initialize it and add it to the local
            DigestScheme digestAuth = new DigestScheme();
            digestAuth.overrideParamter("realm", "Digest realm for COMPOSE IDM");
            digestAuth.overrideParamter("nonce", DigestScheme.createCnonce());
            authCache.put(target, digestAuth);

            // Add AuthCache to the execution context
            HttpClientContext localContext = HttpClientContext.create();
            localContext.setAuthCache(authCache);

            
            CloseableHttpResponse response  = null;
        	try {
        		HttpPost httpPost = new HttpPost(uri);
        		StringEntity requestEntity = new StringEntity(
        			    JsonAsString,
        			    "UTF-8");
        		httpPost.addHeader("Content-Type", "application/json");
        		httpPost.setEntity(requestEntity);
        		response = httpclient.execute(target, httpPost, localContext);
				//System.out.println(EntityUtils.toString(response.getEntity()));
				return response;
			
        	} catch (ClientProtocolException e) {
				throw new PDPServioticyException(500, "A problem with the connection occurred, or the connection was aborted when calling COMPOSE IDM", "there is a problem with the network connection");
		    
			} catch (IOException e) {
				throw new PDPServioticyException(500, "there is an HTTP protocol problem when calling COMPOSE IDM", "there is an HTTP protocol problem ");
			    
			}
	}
	
	public String getInformationForUser(String accessToken) throws PDPServioticyException
	{
		Map<String,String> headers = new HashMap<String, String>();
		headers.put("Authorization","Bearer "+accessToken);
		headers.put("Content-Type","application/json;charset=UTF-8");
		CloseableHttpResponse res = internalGetToIDM("/idm/user/info/", headers);
		try {
			 if(res.getStatusLine().getStatusCode()!=200)
				 return null;
			String ret =  EntityUtils.toString(res.getEntity());
			
			return ret;
		} catch (ParseException e) {
			throw new PDPServioticyException(500, "A problem with the connection occurred, response from COMPOSE IDM could not be parsed", "response from IDM could not be parsed");
		} catch (IOException e) {
			throw new PDPServioticyException(500, "there is an HTTP protocol problem when calling COMPOSE IDM", "there is an HTTP protocol problem ");
		}	
		finally{
			try {
				((CloseableHttpResponse) res).close();
			} catch (IOException e) {
			//log information?
		}
  }
	}
	
	public void  deleteSO(String protocol, String idmHost, int idmPort, String soid, String token) throws PDPServioticyException
	{
		//JsonNode node = so.findValue("lastModified");
		//JsonNode idNode = so.findValue("id");
		ResponseEntity<Object> responseEntityDetails =null;
		try{
			RestTemplate restTemplate = new RestTemplate();
			HttpHeaders header = new HttpHeaders();
		    header.set("Authorization", token);
		    HttpEntity<String> serviceDetails = new HttpEntity<String>(header);
	
		    responseEntityDetails = restTemplate.exchange(
		    		 protocol+"://"+idmHost+(idmPort>0?":"+idmPort: "")+"idm/serviceobject/" + soid, HttpMethod.GET,
		                serviceDetails, Object.class);
	
		    @SuppressWarnings("unchecked")
		    LinkedHashMap<String, Object> soCreateResponse = (LinkedHashMap<String, Object>) responseEntityDetails
		                .getBody();
	
		    if(HttpStatus.OK.equals(responseEntityDetails.getStatusCode()))    
		    {    
		        long timestamp = (long) soCreateResponse.get("lastModified");
		        sendDeleteToIDM(protocol+"://"+idmHost+(idmPort>0?":"+idmPort: "")+"/idm/serviceobject/"+soid,timestamp, token);
		    }
		}
		catch( HttpClientErrorException ex)
		{
			//System.err.println(ex.toString());
			System.err.println("ex:"+ex.getResponseBodyAsString()+" code: "+ex.getStatusText());
        	throw new PDPServioticyException(ex.getStatusCode().value(), "Error when deleting or reading the Service Object "+ex.getStatusText(), "response from IDM when deleting entity "+ex.getResponseBodyAsString());
		}
	}
	
	//TODO delete:  curl --digest -u "composecontroller:composecontrollerpassword" -H "If-Unmodified-Since: 1400862183000"   -H "Content-Type: application/json;charset=UTF-8" -d  '{"authorization": "'"Bearer $TOKEN"'"}' -X DELETE http://localhost:8080/idm/serviceobject/so1meid
	public void  sendDeleteToIDM(String uri, long timestampLastModified, String userAccessToken) throws PDPServioticyException, HttpClientErrorException
	{
			RestTemplate digestRestTemplate = digestRestTemplate();
		 	
			AuthenticatedEmptyMessage authenticateEmptyMes = new AuthenticatedEmptyMessage();
			authenticateEmptyMes.setAuthorization(userAccessToken);
	        HttpHeaders header = new HttpHeaders();
	        header.set("If-Unmodified-Since",
	                String.valueOf(timestampLastModified));
	        HttpEntity<AuthenticatedEmptyMessage> deletionEntity = new HttpEntity<AuthenticatedEmptyMessage>(
	                authenticateEmptyMes, header);

	        ResponseEntity<Object> responseEntityDeletion = digestRestTemplate
	                .exchange(uri,
	                        HttpMethod.DELETE, deletionEntity, Object.class);

	        if(!HttpStatus.OK.equals(responseEntityDeletion.getStatusCode()))
	        {
	        	throw new PDPServioticyException(responseEntityDeletion.getStatusCode().value(), "A problem with the connection occurred when deleting, unexpected response code "+responseEntityDeletion.getStatusCode().toString(), "response from IDM when deleting entity "+responseEntityDeletion.getStatusCode().toString()+" response "+responseEntityDeletion.toString());
	        	//TODO throw exception
	        }
	        
	}
    
}