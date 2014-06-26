package de.passau.uni.sec.compose.pdp.servioticy.idm;



import java.io.IOException;
import java.util.List;

import org.apache.http.HttpHost;
import org.apache.http.NameValuePair;
import org.apache.http.auth.AuthScope;
import org.apache.http.auth.UsernamePasswordCredentials;
import org.apache.http.client.AuthCache;
import org.apache.http.client.ClientProtocolException;
import org.apache.http.client.CredentialsProvider;
import org.apache.http.client.entity.UrlEncodedFormEntity;
import org.apache.http.client.methods.CloseableHttpResponse;
import org.apache.http.client.methods.HttpGet;
import org.apache.http.client.methods.HttpPost;
import org.apache.http.client.protocol.HttpClientContext;
import org.apache.http.entity.StringEntity;
import org.apache.http.impl.auth.DigestScheme;
import org.apache.http.impl.client.BasicAuthCache;
import org.apache.http.impl.client.BasicCredentialsProvider;
import org.apache.http.impl.client.CloseableHttpClient;
import org.apache.http.impl.client.HttpClients;
import org.apache.http.protocol.HTTP;

import de.passau.uni.sec.compose.pdp.servioticy.exception.PDPServioticyException;

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
    
}