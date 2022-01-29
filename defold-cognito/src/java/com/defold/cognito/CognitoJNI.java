package com.defold.cognito;

public class CognitoJNI implements IResultListener {

    public CognitoJNI() {
    }

    @Override
    public native void onResult(int responseCode, String result, long cmdHandle);
}
