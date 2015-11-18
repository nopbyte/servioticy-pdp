package de.passau.uni.sec.compose.pdp.servioticy;

import java.util.Map;
import java.util.HashMap;

import com.fasterxml.jackson.databind.JsonNode;

public class PermissionCacheObject
{
	private boolean permission =false;
	private Object cache;


	public boolean isPermission() {
		return permission;
	}
	public void setPermission(boolean permission) {
		this.permission = permission;
	}
	public Object getCache() {
		return cache;
	}
	public void setCache(Object cache) {
		this.cache = cache;
	}
	public String getUserId()
	{
		String ret = null;
		if(this.cache != null && this.cache instanceof Map)
		{
			Map temp = (Map<String, Object>)this.cache;
			if(temp.containsKey("UserId"))
				ret = (String) temp.get("UserId");
		}
		return ret;
	}
	
	public JsonNode getUserInfo()
	{
		JsonNode ret = null;
		if(this.cache != null && this.cache instanceof Map)
		{
			Map temp = (Map<String, Object>)this.cache;
			if(temp.containsKey("userInfo"))
				ret = (JsonNode) temp.get("userInfo");
		}
		return ret;
	}
	
	public JsonNode getSecurityMetaData()
	{
		JsonNode ret = null;
		if(this.cache != null && this.cache instanceof Map)
		{
			Map temp = (Map<String, Object>)this.cache;
			if(temp.containsKey("SecurityMetaData"))
			ret = (JsonNode) temp.get("SecurityMetaData");
		}
		return ret;
	}

	public void setUserId(String user_id)
	{
		if(this.cache != null && this.cache instanceof Map)
		{
			((Map<String, Object>)this.cache).put("UserId", user_id);
		} else {
			Map<String, Object> tempMapCache = new HashMap<String, Object>();
			tempMapCache.put("UserId", user_id);
			this.setCache(tempMapCache);
		}
	}

	public void setStream(String stream)
	{
		if(this.cache != null && this.cache instanceof Map)
		{
			((Map<String, Object>)this.cache).put("Stream", stream);
		} else {
			Map<String, Object> tempMapCache = new HashMap<String, Object>();
			tempMapCache.put("Stream", stream);
			this.setCache(tempMapCache);
		}
	}
	
	public String getStream()
	{
		String ret = null;
		if(this.cache != null && this.cache instanceof Map)
		{
			Map temp = (Map<String, Object>)this.cache;
			if(temp.containsKey("Stream"))
				ret = (String) temp.get("Stream");
		}
		return ret;
	}
	
	public void setSubscriptionInfo(String subInfo)
	{
		if(this.cache != null && this.cache instanceof Map)
		{
			((Map<String, Object>)this.cache).put("SubInfo", subInfo);
		} else {
			Map<String, Object> tempMapCache = new HashMap<String, Object>();
			tempMapCache.put("SubInfo", subInfo);
			this.setCache(tempMapCache);
		}
	}

	public String getSubscriptionInfo()
	{
		String ret = null;
		if(this.cache != null && this.cache instanceof Map)
		{
			Map temp = (Map<String, Object>)this.cache;
			if(temp.containsKey("SubInfo"))
				ret = (String) temp.get("SubInfo");
		}
		return ret;
	}
	
	
	public void setDecryptedUpdate(JsonNode subInfo)
	{
		if(this.cache != null && this.cache instanceof Map)
		{
			((Map<String, Object>)this.cache).put("decryptedUpdate", subInfo);
		} else {
			Map<String, Object> tempMapCache = new HashMap<String, Object>();
			tempMapCache.put("decryptedUpdate", subInfo);
			this.setCache(tempMapCache);
		}
	}
	
	public JsonNode getDecryptedUpdate()
	{
		JsonNode ret = null;
		if(this.cache != null && this.cache instanceof Map)
		{
			Map temp = (Map<String, Object>)this.cache;
			if(temp.containsKey("decryptedUpdate"))
				ret = (JsonNode) temp.get("decryptedUpdate");
		}
		return ret;
	}
	public void setUserInfo(JsonNode userInfo) {
		if(this.cache != null && this.cache instanceof Map)
		{
			((Map<String, Object>)this.cache).put("userInfo", userInfo);
		} else {
			Map<String, Object> tempMapCache = new HashMap<String, Object>();
			tempMapCache.put("userInfo", userInfo);
			this.setCache(tempMapCache);
		}		
	}
	
}





