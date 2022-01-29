package com.defold.cognito;

import java.math.BigInteger;
import java.text.SimpleDateFormat;
import java.util.ArrayList;
import java.util.Date;
import java.util.Iterator;
import java.util.List;
import java.util.Map;
import java.util.HashMap;
import java.util.concurrent.ArrayBlockingQueue;
import java.util.concurrent.BlockingQueue;

import org.json.JSONException;
import org.json.JSONObject;
import org.json.JSONArray;

import android.app.Activity;
import android.content.Context;
import android.util.Log;

import com.amazonaws.ClientConfiguration;
import com.amazonaws.auth.AnonymousAWSCredentials;
import com.amazonaws.mobileconnectors.cognitoidentityprovider.CognitoDevice;
import com.amazonaws.mobileconnectors.cognitoidentityprovider.CognitoUser;
import com.amazonaws.mobileconnectors.cognitoidentityprovider.CognitoUserAttributes;
import com.amazonaws.mobileconnectors.cognitoidentityprovider.CognitoUserCodeDeliveryDetails;
import com.amazonaws.mobileconnectors.cognitoidentityprovider.CognitoUserDetails;
import com.amazonaws.mobileconnectors.cognitoidentityprovider.CognitoUserPool;
import com.amazonaws.mobileconnectors.cognitoidentityprovider.CognitoUserSession;
import com.amazonaws.mobileconnectors.cognitoidentityprovider.continuations.AuthenticationContinuation;
import com.amazonaws.mobileconnectors.cognitoidentityprovider.continuations.AuthenticationDetails;
import com.amazonaws.mobileconnectors.cognitoidentityprovider.continuations.ChallengeContinuation;
import com.amazonaws.mobileconnectors.cognitoidentityprovider.continuations.ForgotPasswordContinuation;
import com.amazonaws.mobileconnectors.cognitoidentityprovider.continuations.MultiFactorAuthenticationContinuation;
import com.amazonaws.mobileconnectors.cognitoidentityprovider.exceptions.CognitoParameterInvalidException;
import com.amazonaws.mobileconnectors.cognitoidentityprovider.handlers.AuthenticationHandler;
import com.amazonaws.mobileconnectors.cognitoidentityprovider.handlers.ForgotPasswordHandler;
import com.amazonaws.mobileconnectors.cognitoidentityprovider.handlers.GetDetailsHandler;
import com.amazonaws.mobileconnectors.cognitoidentityprovider.handlers.GenericHandler;
import com.amazonaws.mobileconnectors.cognitoidentityprovider.handlers.SignUpHandler;
import com.amazonaws.mobileconnectors.cognitoidentityprovider.handlers.VerificationHandler;

import com.amazonaws.regions.Region;
import com.amazonaws.regions.Regions;
import com.amazonaws.services.cognitoidentityprovider.AmazonCognitoIdentityProviderClient;
import com.amazonaws.services.cognitoidentityprovider.model.SignUpResult;
import com.amazonaws.services.cognitoidentityprovider.model.UserPoolAddOnNotEnabledException;

public class Cognito {
    public static final String TAG = "Cognito";

    private Activity activity;
    private CognitoUserPool userPool;
    private CognitoUserSession userSession;

    public Cognito(Activity activity) {
        this.activity = activity;
    }

    /**
     * Called from Lua.
     */
    public void init(String poolId, String clientId, String region) {
        AmazonCognitoIdentityProviderClient identityProviderClient = new AmazonCognitoIdentityProviderClient(new AnonymousAWSCredentials(), new ClientConfiguration());
        identityProviderClient.setRegion(Region.getRegion(region));
        ClientConfiguration clientConfiguration = new ClientConfiguration();
        Context ctx = this.activity.getApplicationContext();
        userPool = new CognitoUserPool(ctx, poolId, clientId, null, identityProviderClient);
    }

    /**
     * Called from Lua.
     */
    public void confirmPassword(String email, String password, String code, final IResultListener resultListener, final long commandPtr) {
        Log.d(TAG, "confirmPassword()");

        CognitoUser user = userPool.getUser(email);

        ForgotPasswordHandler fph = new ForgotPasswordHandler() {
            @Override
            public void onSuccess() {
                Log.e(TAG, "confirmPassword.onSuccess");
                login(email, password, resultListener, commandPtr);
            }

            @Override
            public void getResetCode(ForgotPasswordContinuation continuation) {

            }

            @Override
            public void onFailure(Exception exception) {
                resultListener.onResult(0, cognitoErrorToJson(exception).toString(), commandPtr);
            }
        };
        user.confirmPasswordInBackground(code, password, fph);
    }

    /**
     * Called from Lua.
     */
    public void confirmSignUp(String userId, String confirmationCode, final IResultListener resultListener, final long commandPtr) {
        CognitoUser user = userPool.getUser(userId);

        boolean forcedAliasCreation = false;

        GenericHandler confirmationCallback = new GenericHandler() {

            @Override
            public void onSuccess() {
                Log.e(TAG, "confirmSignUp.onSuccess");
                getSession(resultListener, commandPtr);
            }

            @Override
            public void onFailure(Exception exception) {
                resultListener.onResult(0, cognitoErrorToJson(exception).toString(), commandPtr);
            }
        };
        user.confirmSignUpInBackground(confirmationCode, forcedAliasCreation, confirmationCallback);
    }

    /**
     * Called from Lua.
     */
    public void forgotPassword(String email, final IResultListener resultListener, final long commandPtr) {
        CognitoUser user = userPool.getUser(email);

        ForgotPasswordHandler fph = new ForgotPasswordHandler() {
            @Override
            public void onSuccess() {
                Log.e(TAG, "forgotPassword.onSuccess");
            }

            @Override
            public void getResetCode(ForgotPasswordContinuation continuation) {
                Log.e(TAG, "forgotPassword.getResetCode");
                JSONObject obj = new JSONObject();
                try {
                    // for convenience sake
                    obj.put("userConfirmed", true);
                    obj.put("getResetCode", true);
                } catch (JSONException e) {
                    e.printStackTrace();
                }
                resultListener.onResult(1, obj.toString(), commandPtr);
            }

            @Override
            public void onFailure(Exception exception) {
                resultListener.onResult(0, cognitoErrorToJson(exception).toString(), commandPtr);
            }
        };
        user.forgotPasswordInBackground(fph);
    }

    /**
     * Called from Lua.
     */
    public void login(String userId, String password, final IResultListener resultListener, final long commandPtr) {
        Log.d(TAG, "login()");

        if (userId == null || userId.length() == 0) return;

        CognitoUser user = userPool.getUser(userId);

        Cognito parent = this;

        AuthenticationHandler authenticationHandler = new AuthenticationHandler() {
            @Override
            public void onSuccess(CognitoUserSession userSession, CognitoDevice newDevice) {
                Log.e(TAG, "onSuccess");
                parent.userSession = userSession;

                GetDetailsHandler getDetailsHandler = new GetDetailsHandler() {
                    @Override
                    public void onSuccess(CognitoUserDetails cognitoUserDetails) {
                        CognitoUserAttributes attributes = cognitoUserDetails.getAttributes();

                        JSONObject attributesObj = new JSONObject();
                        JSONObject accessToken = new JSONObject();
                        JSONObject refreshToken = new JSONObject();
                        JSONObject obj = new JSONObject();
                        try {
                            // for convenience sake
                            obj.put("userConfirmed", true);
                            obj.put("userName", userSession.getUsername());

                            accessToken.put("jwtToken", userSession.getAccessToken().getJWTToken());
                            obj.put("accessToken", accessToken);

                            refreshToken.put("token", userSession.getRefreshToken().getToken());
                            obj.put("refreshToken", refreshToken);

                            for (Map.Entry<String,String> entry : attributes.getAttributes().entrySet())
                                attributesObj.put(entry.getKey(), entry.getValue());
                            obj.put("attributes", attributesObj);
                        } catch (JSONException e) {
                            e.printStackTrace();
                        }

                        resultListener.onResult(1, obj.toString(), commandPtr);
                    }

                    @Override
                    public void onFailure(Exception exception) {
                        JSONObject obj = cognitoErrorToJson(exception);
                    }
                };

                try {
                    user.getDetailsInBackground(getDetailsHandler);
                } catch (CognitoParameterInvalidException e) {
                    resultListener.onResult(0, cognitoErrorToJson(e).toString(), commandPtr);
                }
            }

            @Override
            public void getAuthenticationDetails(AuthenticationContinuation authenticationContinuation, String userId) {
                Log.e(TAG, "login.getAuthenticationDetails");
                AuthenticationDetails authenticationDetails = new AuthenticationDetails(userId, password, null);
                authenticationContinuation.setAuthenticationDetails(authenticationDetails);
                authenticationContinuation.continueTask();
            }

            @Override
            public void getMFACode(MultiFactorAuthenticationContinuation multiFactorAuthenticationContinuation) {
                Log.e(TAG, "getMFACode");
                // TODO:
                multiFactorAuthenticationContinuation.setMfaCode(TAG);
                multiFactorAuthenticationContinuation.continueTask();
            }

            @Override
            public void authenticationChallenge(ChallengeContinuation continuation) {
                Log.e(TAG, "authenticationChallenge");
            }

            @Override
            public void onFailure(Exception exception) {
                Log.e(TAG, "onFailure");
                Log.e(TAG, exception.toString());
                resultListener.onResult(0, cognitoErrorToJson(exception).toString(), commandPtr);
            }
        };

        try {
            user.getSessionInBackground(authenticationHandler);
        } catch (CognitoParameterInvalidException e) {
            resultListener.onResult(0, cognitoErrorToJson(e).toString(), commandPtr);
        }
    }

    /**
     * Called from Lua.
     */
    public void getSession(final IResultListener resultListener, final long commandPtr) {
        Log.d(TAG, "getSession()");

        CognitoUser user = userPool.getCurrentUser();

        Cognito parent = this;

        AuthenticationHandler authenticationHandler = new AuthenticationHandler() {
            @Override
            public void onSuccess(CognitoUserSession userSession, CognitoDevice newDevice) {
                Log.e(TAG, "onSuccess");
                parent.userSession = userSession;

                GetDetailsHandler getDetailsHandler = new GetDetailsHandler() {
                    @Override
                    public void onSuccess(CognitoUserDetails cognitoUserDetails) {
                        CognitoUserAttributes attributes = cognitoUserDetails.getAttributes();

                        JSONObject attributesObj = new JSONObject();
                        JSONObject accessToken = new JSONObject();
                        JSONObject refreshToken = new JSONObject();
                        JSONObject obj = new JSONObject();
                        try {
                            // for convenience sake
                            obj.put("userConfirmed", true);
                            obj.put("userName", userSession.getUsername());

                            accessToken.put("jwtToken", userSession.getAccessToken().getJWTToken());
                            obj.put("accessToken", accessToken);

                            refreshToken.put("token", userSession.getRefreshToken().getToken());
                            obj.put("refreshToken", refreshToken);

                            for (Map.Entry<String,String> entry : attributes.getAttributes().entrySet())
                                attributesObj.put(entry.getKey(), entry.getValue());
                            obj.put("attributes", attributesObj);
                        } catch (JSONException e) {
                            e.printStackTrace();
                        }

                        resultListener.onResult(1, obj.toString(), commandPtr);
                    }

                    @Override
                    public void onFailure(Exception exception) {
                        JSONObject obj = cognitoErrorToJson(exception);
                    }
                };


                try {
                    user.getDetailsInBackground(getDetailsHandler);
                } catch (CognitoParameterInvalidException e) {
                    resultListener.onResult(0, cognitoErrorToJson(e).toString(), commandPtr);
                }

            }

            @Override
            public void getAuthenticationDetails(AuthenticationContinuation authenticationContinuation, String userId) {
                Log.e(TAG, "getSession.getAuthenticationDetails");
                parent.userSession = userSession;

                JSONObject obj = new JSONObject();
                try {
                    // for convenience sake
                    obj.put("userConfirmed", true);
                    obj.put("userId", user.getUserId());
                    obj.put("getAuthenticationDetails", true);
                } catch (JSONException e) {
                    e.printStackTrace();
                }
                resultListener.onResult(1, obj.toString(), commandPtr);
            }

            @Override
            public void getMFACode(MultiFactorAuthenticationContinuation multiFactorAuthenticationContinuation) {
                Log.e(TAG, "getMFACode");
                multiFactorAuthenticationContinuation.setMfaCode(TAG);
                multiFactorAuthenticationContinuation.continueTask();
            }

            @Override
            public void authenticationChallenge(ChallengeContinuation continuation) {
                Log.e(TAG, "authenticationChallenge");
            }

            @Override
            public void onFailure(Exception exception) {
                Log.e(TAG, "onFailure");
                Log.e(TAG, exception.toString());
                resultListener.onResult(0, cognitoErrorToJson(exception).toString(), commandPtr);
            }
        };

        try {
            user.getSessionInBackground(authenticationHandler);
        } catch (CognitoParameterInvalidException e) {
            resultListener.onResult(0, cognitoErrorToJson(e).toString(), commandPtr);
        }
    }

    public void signUp(String userId, String password, final IResultListener resultListener, final long commandPtr) {
        CognitoUserAttributes userAttributes = new CognitoUserAttributes();
        userAttributes.addAttribute("email", userId);

        SignUpHandler signupCallback = new SignUpHandler() {

            @Override
            public void onSuccess(CognitoUser user, SignUpResult signUpResult) {
                Log.e(TAG, "signup.onSuccess");
                JSONObject obj = new JSONObject();

                // NOTE: easier if we just inject a synthetic UserNotConfirmedException
                // TODO: worth allowing user to disable this behaviour
                if (!signUpResult.getUserConfirmed()) {
                    try {
                        obj.put("code", "UserNotConfirmedException");
                    } catch (JSONException e) {
                        e.printStackTrace();
                    }
                    resultListener.onResult(0, obj.toString(), commandPtr);
                    return;
                }

                try {
                    obj.put("userConfirmed", signUpResult.getUserConfirmed());
                    obj.put("userName", userSession.getUsername());
                } catch (JSONException e) {
                    e.printStackTrace();
                }
                resultListener.onResult(1, obj.toString(), commandPtr);
            }

            @Override
            public void onFailure(Exception exception) {
                Log.e(TAG, "signup.onFailure");
                Log.e(TAG, exception.toString());
                resultListener.onResult(0, cognitoErrorToJson(exception).toString(), commandPtr);
            }
        };

        userPool.signUpInBackground(userId, password, userAttributes, null, signupCallback);
    }

    /**
     * Called from Lua.
     */
    public void signOut() {
        CognitoUser user = userPool.getCurrentUser();
        user.signOut();
    }

    /**
     * Called from Lua.
     */
    public void globalSignOut(final IResultListener resultListener, final long commandPtr) {
        CognitoUser user = userPool.getCurrentUser();
        GenericHandler gh = new GenericHandler() {
            @Override
            public void onSuccess() {
                JSONObject obj = new JSONObject();
                try {
                    obj.put("signedOut", true);
                    obj.put("userConfirmed", true);
                    obj.put("userId", user.getUserId());
                } catch (JSONException e) {
                    e.printStackTrace();
                }
                resultListener.onResult(1, obj.toString(), commandPtr);
            }

            @Override
            public void onFailure(Exception exception) {
                resultListener.onResult(0, cognitoErrorToJson(exception).toString(), commandPtr);
            }
        };
        user.globalSignOutInBackground(gh);
    }

    /**
     * Called from Lua.
     */
    public void resendConfirmationCode(String userId, final IResultListener resultListener, final long commandPtr) {
        CognitoUser user = userPool.getUser(userId);
        VerificationHandler vh = new VerificationHandler() {
            @Override
            public void onSuccess(CognitoUserCodeDeliveryDetails verificationCodeDeliveryMedium) {
                JSONObject obj = new JSONObject();
                try {
                    obj.put("userConfirmed", false);
                    obj.put("userId", user.getUserId());
                } catch (JSONException e) {
                    e.printStackTrace();
                }
                resultListener.onResult(1, obj.toString(), commandPtr);
            }

            @Override
            public void onFailure(Exception exception) {
                resultListener.onResult(0, cognitoErrorToJson(exception).toString(), commandPtr);
            }
        };
        user.resendConfirmationCodeInBackground(vh);
    }

    private JSONObject cognitoErrorToJson(Exception exception) {
        String errorCode = exception.toString().split(":")[0].replaceAll("com.amazonaws.services.cognitoidentityprovider.model.", "");

        JSONObject obj = new JSONObject();
        try {
            obj.put("code", errorCode);
        } catch (JSONException e) {
            e.printStackTrace();
        }
        return obj;
    }
}
