package com.defold.cognito;

public interface IResultListener {
	public void onResult(int resultCode, String result, long cmdHandle);
}
