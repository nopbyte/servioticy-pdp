package de.passau.uni.sec.compose.pdp.servioticy;

import java.util.Map;

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
		if(cache instanceof Map)
		{
			Map temp = (Map<String, Object>)this.cache;
			if(temp.containsKey("UserId"))
				ret = (String) temp.get("UserId");
		}
		return ret;
	}
	public JsonNode getSecurityMetaData()
	{
		Map temp = (Map<String, Object>)this.cache;
		JsonNode ret = (JsonNode) temp.get("SecurityMetaData");
		return ret;
	}
}
