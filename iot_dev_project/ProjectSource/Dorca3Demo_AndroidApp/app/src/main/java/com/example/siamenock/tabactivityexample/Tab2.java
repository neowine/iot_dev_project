package com.example.siamenock.tabactivityexample;

/**
 * Created by siamenock on 2018-02-09.
 */

import android.os.Bundle;
import android.os.Handler;
import android.support.v4.app.Fragment;
import android.util.Log;
import android.view.LayoutInflater;
import android.view.View;
import android.view.ViewGroup;
import android.widget.Button;
import android.widget.CompoundButton;
import android.widget.TextView;
import android.widget.ToggleButton;

import org.eclipse.paho.android.service.MqttAndroidClient;
import org.eclipse.paho.client.mqttv3.IMqttActionListener;
import org.eclipse.paho.client.mqttv3.IMqttDeliveryToken;
import org.eclipse.paho.client.mqttv3.IMqttToken;
import org.eclipse.paho.client.mqttv3.MqttCallback;
import org.eclipse.paho.client.mqttv3.MqttClient;
import org.eclipse.paho.client.mqttv3.MqttException;
import org.eclipse.paho.client.mqttv3.MqttMessage;

import java.io.BufferedReader;
import java.io.DataOutputStream;
import java.io.InputStreamReader;
import java.net.HttpURLConnection;
import java.net.URL;
import java.util.logging.Level;
import java.util.logging.Logger;


public class Tab2 extends  Fragment implements View.OnClickListener{
    public View view;
    public Button btnGetData, btnRedOn, btnRedOff, btnGreenOn, btnGreenOff, btnBlueOn, btnBlueOff;
    public ToggleButton toggleAuto, toggleRaspberry, toggleArduino;
    public TextView textViewData, textViewData2;
    public Handler handler;

    private static CSEBase csebase = new CSEBase();
    private static AE ae = new AE();
    private static String TAG;
    private static String CSE_IP;
    private static String CSE_PORT;
    private static String CSE_NAME;
    private static String MQTT_PORT;
    private String ServiceAEName;
    private String targetTAS;
    private String AE_NAME;
    private boolean encrypt_enable = true;


    private String MQTT_Req_Topic = "";
    private String MQTT_Resp_Topic = "";
    private MqttAndroidClient mqttClient = null;
    private AES256Tool a256 = null;

    @Override
    public View onCreateView(LayoutInflater inflater, ViewGroup container, Bundle savedInstanceState) {
        CSE_IP         = new String (_Config.CSE_IP);
        CSE_PORT       = new String (_Config.CSE_PORT);
        CSE_NAME       = new String (_Config.CSE_NAME);
        MQTT_PORT      = new String (_Config.MQTT_PORT);
        ServiceAEName  = new String (_Config.ServiceAEName);
        targetTAS      = new String (_Config.targetTAS);
        AE_NAME        = new String (_Config.AE_NAME);
        TAG            = new String (_Config.TAG);
        a256 = AES256Tool.getInstance();

        this.view = inflater.inflate(R.layout.tab2, container, false);

        toggleRaspberry = (ToggleButton) view.findViewById(R.id.toggleRaspberry);
        toggleArduino   = (ToggleButton) view.findViewById(R.id.toggleArduino);

        //toggleAuto      = (ToggleButton) view.findViewById(R.id.toggleAuto);
        btnGetData      = (Button)       view.findViewById(R.id.btnGetData);
        btnRedOn        = (Button)       view.findViewById(R.id.btnRedOn);
        btnRedOff       = (Button)       view.findViewById(R.id.btnRedOff);
        btnGreenOn      = (Button)       view.findViewById(R.id.btnGreenOn);
        btnGreenOff     = (Button)       view.findViewById(R.id.btnGreenOff);
        btnBlueOn       = (Button)       view.findViewById(R.id.btnBlueOn);
        btnBlueOff      = (Button)       view.findViewById(R.id.btnBlueOff);

        textViewData    = (TextView)     view.findViewById(R.id.textViewData);
        textViewData2   = (TextView)     view.findViewById(R.id.textViewData2);


        //toggleAuto.     setOnClickListener(this);
        btnGetData.     setOnClickListener(this);
        btnRedOn.       setOnClickListener(this);
        btnRedOff.      setOnClickListener(this);
        btnGreenOn.     setOnClickListener(this);
        btnGreenOff.    setOnClickListener(this);
        btnBlueOn.      setOnClickListener(this);
        btnBlueOff.     setOnClickListener(this);

        toggleRaspberry.setOnClickListener(this);
        toggleArduino.  setOnClickListener(this);

        toggleRaspberry.setChecked(true);

        a256 = AES256Tool.getInstance();
        handler = new Handler();
        //GetAEInfo();  // AE setting is done when password set
        return this.view;
    }
    public void GetAEInfo() {
        csebase.setInfo(CSE_IP, CSE_PORT, CSE_NAME, MQTT_PORT);
        //csebase.setInfo("203.253.128.151","7579","Mobius","1883");
        // AE Create for Android AE
        ae.setAppName(AE_NAME);
        aeCreateRequest aeCreate = new aeCreateRequest();
        aeCreate.setReceiver(new IReceived() {
            public void getResponseBody(final String msg) {
                handler.post(new Runnable() {
                    public void run() {
                        Log.d(TAG, "** AE Create ResponseCode[" + msg +"]");
                        if( Integer.parseInt(msg) == 201 ){
                            MQTT_Req_Topic = "/oneM2M/req/Mobius/"+ae.getAEid()+"_sub"+"/#";
                            MQTT_Resp_Topic = "/oneM2M/resp/Mobius/"+ae.getAEid()+"_sub"+"/xml";
                            //Log.d(TAG, "RTopic["+ MQTT_Req_Topic+"]");
                            //Log.d(TAG, "ResTopic["+ MQTT_Resp_Topic+"]");
                        }
                        else { // If AE is Exist , GET AEID
                            aeRetrieveRequest aeRetrive = new aeRetrieveRequest();
                            aeRetrive.setReceiver(new IReceived() {
                                public void getResponseBody(final String resmsg) {
                                    handler.post(new Runnable() {
                                        public void run() {
                                            Log.d(TAG, "** AE Retrive ResponseCode[" + resmsg +"]");
                                            MQTT_Req_Topic = "/oneM2M/req/Mobius/"+ae.getAEid()+"_sub"+"/#";
                                            MQTT_Resp_Topic = "/oneM2M/resp/Mobius/"+ae.getAEid()+"_sub"+"/xml";
                                            //Log.d(TAG, "RTopic["+ MQTT_Req_Topic+"]");
                                            //Log.d(TAG, "ResTopic["+ MQTT_Resp_Topic+"]");
                                        }
                                    });
                                }
                            });
                            aeRetrive.start();
                        }
                    }
                });
            }
        });
        aeCreate.start();
    }

    @Override
    public void onClick(View v) {
        switch (v.getId()) {
            case R.id.toggleRaspberry:{
                toggleRaspberry.setChecked(true);
                toggleArduino.setChecked(false);
                targetTAS = "raspberryPi";
                encrypt_enable = true;
                break;
            }
            case R.id.toggleArduino: {
                toggleArduino.setChecked(true);
                toggleRaspberry.setChecked(false);
                targetTAS = "arduino";
                encrypt_enable = false;
                break;
            }

            case R.id.btnGetData: {
                RetrieveRequest req = new RetrieveRequest(targetTAS + "-out");
                textViewData.setText("waiting reply...");
                req.setReceiver(new IReceived() {
                    public void getResponseBody(final String msg) {
                        handler.post(new Runnable() {
                            public void run() {
                                String con       = getJsonComponent(msg, "con");
                                String container = getJsonComponent(msg, "container");
                                String display;
                                display =  "";
                                display += "container\t: " + container + "\n";
                                display += "received \t: " + con + "\n";
                                display += "전문\n" + msg;
                                textViewData.setText(display);
                                display = "";
                                display += "container\t: " + container + "\n";
                                display += "decrypted\t: " + a256.AES_Decode(con); // do something on con   // 암호
                                textViewData2.setText(display);
                            }
                        });
                    }
                });

                req.start();
                break;
            }
            // mobius server로부터 최신정보를 자동으로 받는 subscribe 기능.
            // 서버 코드에 버그가 있어서 기능 삭제함. (5초 정도만 지속 가능)
            //case R.id.toggleAuto:{
            //  if (toggleAuto.isChecked()) {
            case -1:{
                if(true){
                    textViewData.setText("send auto check request");
                    Log.d(TAG, "MQTT Create");
                    MQTT_Create(true);
                    textViewData.setText("send auto check request....");
                } else {
                    //textViewData.setText("exit auto check request");
                    Log.d(TAG, "MQTT Close");
                    MQTT_Create(false);
                    //textViewData.setText("exit auto check request....");
                }
                break;
            }
            case R.id.btnRedOn: {
                msgSendDisplay(targetTAS + "-in", "LED_Red ON");
                break;
            }
            case R.id.btnRedOff: {
                msgSendDisplay(targetTAS + "-in","LED_Red OFF");
                break;
            }
            case R.id.btnGreenOn: {
                msgSendDisplay(targetTAS + "-in", "LED_Green ON");
                break;
            }
            case R.id.btnGreenOff: {
                msgSendDisplay(targetTAS + "-in","LED_Green OFF");
                break;
            }
            case R.id.btnBlueOn: {
                msgSendDisplay(targetTAS + "-in", "LED_Blue ON");
                break;
            }
            case R.id.btnBlueOff: {
                msgSendDisplay(targetTAS + "-in","LED_Blue OFF");
                break;
            }
        }
    }

    @Override
    public void onStart() {
        super.onStart();
    }

    @Override
    public void onStop() {
        super.onStop();
    }

    /* MQTT Subscription */
    public void MQTT_Create(boolean mtqqStart) {
        if (mtqqStart && mqttClient == null) {
            /* Subscription Resource Create to Yellow Turtle */
            SubscribeResource subcribeResource = new SubscribeResource();
            subcribeResource.setReceiver(new IReceived() {
                public void getResponseBody(final String msg) {
                    handler.post(new Runnable() {
                        public void run() {
                            textViewData.setText("**** Subscription Request reply ****\r\n\r\n" + msg);
                        }
                    });
                }
            });
            subcribeResource.start();

            /* MQTT Subscribe */
            mqttClient = new MqttAndroidClient(this.getContext(), "tcp://" + csebase.getHost() + ":" + csebase.getMQTTPort(), MqttClient.generateClientId());
            mqttClient.setCallback(mainMqttCallback);
            try {
                IMqttToken token = mqttClient.connect();
                token.setActionCallback(mainIMqttActionListener);
            } catch (MqttException e) {
                e.printStackTrace();
            }
        } else {
            /* MQTT unSubscribe or Client Close */
            mqttClient.setCallback(null);
            mqttClient.close();
            mqttClient = null;
        }
    }
    /* MQTT Listener */
    private IMqttActionListener mainIMqttActionListener = new IMqttActionListener() {
        @Override
        public void onSuccess(IMqttToken asyncActionToken) {
            Log.d(TAG, "onSuccess");
            String payload = "";
            int mqttQos = 1; /* 0: NO QoS, 1: No Check , 2: Each Check */

            MqttMessage message = new MqttMessage(payload.getBytes());
            try {
                mqttClient.subscribe(MQTT_Req_Topic, mqttQos);
            } catch (MqttException e) {
                e.printStackTrace();
            }
        }

        @Override
        public void onFailure(IMqttToken asyncActionToken, Throwable exception) {
            Log.d(TAG, "onFailure");
        }
    };
    /* MQTT Broker Message Received */
    private MqttCallback mainMqttCallback = new MqttCallback() {
        @Override
        public void connectionLost(Throwable cause) {
            Log.d(TAG, "connectionLost");
        }

        @Override
        public void messageArrived(String topic, MqttMessage message) throws Exception {

            Log.d(TAG, "messageArrived");
            String jstr = message.toString().replaceAll("\t|\n", "");
            String con = getJsonComponent(jstr, "con");
            String container = getJsonComponent(jstr, "sur");
            container.substring(0, container.lastIndexOf('\\'));

            String display;
            display = "**** Sensor Data Subscribe ****\n";
            display += "container\t: " + container + "\n";
            display += "받은 암호문\t: " + con + "\n";
            display += "accepted leng == " + jstr.length() + "\n";
            display += "원문\n" + jstr;
            textViewData.setText(display);
            display = "**** Sensor Data Subscribe ****\n";
            display += "container\t: " + container + "\n";
            display += "decrypted\t : " + a256.AES_Decode(con); // do something on con
            textViewData2.setText(display);

            //Log.d(TAG, "topic:" + topic);
            //Log.d(TAG, "ResMessage:" + message.toString());
            String retrqi = MqttClientRequestParser.notificationJsonParse(message.toString());
            String responseMessage = MqttClientRequest.notificationResponse(retrqi);

            //Log.d(TAG, "MQTT Resp["+responseMessage+"]");
            /* Make xml for MQTT Response Message */
            MqttMessage resmessage = new MqttMessage(responseMessage.getBytes());

            try {
                mqttClient.publish(MQTT_Resp_Topic, resmessage);
            } catch (MqttException e) {
                e.printStackTrace();
            }
        }
        @Override
        public void deliveryComplete(IMqttDeliveryToken token) {
            Log.d(TAG, "deliveryComplete");
        }
    };
    /* Response callback Interface */
    public interface IReceived {
        void getResponseBody(String msg);
    }

    /* Retrieve Sensor */
    class RetrieveRequest extends Thread {
        private final Logger LOG = Logger.getLogger(RetrieveRequest.class.getName());
        private IReceived receiver;
        private String ContainerName = "default_container";

        public RetrieveRequest(String containerName) {
            this.ContainerName = containerName;
        }
        public RetrieveRequest() {}
        public void setReceiver(IReceived hanlder) { this.receiver = hanlder; }

        @Override
        public void run() {
            if(UserFilter.check() == true) {
                try {
                    String sb = csebase.getServiceUrl() + "/" + ServiceAEName + "/" + ContainerName + "/" + "latest";

                    URL mUrl = new URL(sb);

                    HttpURLConnection conn = (HttpURLConnection) mUrl.openConnection();
                    conn.setRequestMethod("GET");
                    conn.setDoInput(true);
                    conn.setDoOutput(false);

                    conn.setRequestProperty("Accept", "application/xml");
                    conn.setRequestProperty("X-M2M-RI", "12345");
                    conn.setRequestProperty("X-M2M-Origin", ae.getAEid());
                    conn.setRequestProperty("nmtype", "long");
                    conn.connect();

                    String strResp = "";
                    BufferedReader in = new BufferedReader(new InputStreamReader(conn.getInputStream()));

                    String strLine = "";
                    while ((strLine = in.readLine()) != null) {
                        strResp += strLine;
                    }

                    if (strResp != "") {
                        receiver.getResponseBody(strResp);
                    }
                    conn.disconnect();

                } catch (Exception exp) {
                    LOG.log(Level.WARNING, exp.getMessage());
                }
            }
        }
    }
    /* Request Control LED */
    class ControlRequest extends Thread {
        private final Logger LOG = Logger.getLogger(ControlRequest.class.getName());
        private IReceived receiver;
        private String container_name = "default_container";

        public ContentInstanceObject contentinstance;
        public ControlRequest(String container, String comm) {


            long time = (new java.util.Date()).getTime();
            comm += ":" + time + ";";       // add timestamp on command. command with old time
            if(encrypt_enable)
                comm = a256.AES_Encode(comm);   // encrypting command //암호

            contentinstance = new ContentInstanceObject();
            contentinstance.setContent(comm);
            container_name = container;
        }
        public void setReceiver(IReceived hanlder) { this.receiver = hanlder; }

        @Override
        public void run() {
            if(UserFilter.check() == true) {
                try {
                    String sb = csebase.getServiceUrl() + "/" + ServiceAEName + "/" + container_name;

                    URL mUrl = new URL(sb);

                    HttpURLConnection conn = (HttpURLConnection) mUrl.openConnection();
                    conn.setRequestMethod("POST");
                    conn.setDoInput(true);
                    conn.setDoOutput(true);
                    conn.setUseCaches(false);
                    conn.setInstanceFollowRedirects(false);

                    conn.setRequestProperty("Accept", "application/xml");
                    conn.setRequestProperty("Content-Type", "application/vnd.onem2m-res+xml;ty=4");
                    conn.setRequestProperty("locale", "ko");
                    conn.setRequestProperty("X-M2M-RI", "12345");
                    conn.setRequestProperty("X-M2M-Origin", ae.getAEid());


                    String reqContent = contentinstance.makeXML();
                    conn.setRequestProperty("Content-Length", String.valueOf(reqContent.length()));

                    DataOutputStream dos = new DataOutputStream(conn.getOutputStream());
                    dos.write(reqContent.getBytes());
                    dos.flush();
                    dos.close();

                    BufferedReader in = new BufferedReader(new InputStreamReader(conn.getInputStream()));

                    String resp = "";
                    String strLine = "";
                    while ((strLine = in.readLine()) != null) {
                        resp += strLine;
                    }
                    if (resp != "") {
                        receiver.getResponseBody(resp);
                    }
                    conn.disconnect();

                } catch (Exception exp) {
                    LOG.log(Level.SEVERE, exp.getMessage());
                }
            }
        }
    }
    /* Reqeust AE Creation */
    class aeCreateRequest extends Thread {
        private final Logger LOG = Logger.getLogger(aeCreateRequest.class.getName());
        String TAG = aeCreateRequest.class.getName();
        private IReceived receiver;
        int responseCode=0;
        public ApplicationEntityObject applicationEntity;
        public void setReceiver(IReceived hanlder) { this.receiver = hanlder; }
        public aeCreateRequest(){
            applicationEntity = new ApplicationEntityObject();
            applicationEntity.setResourceName(ae.getappName());
        }
        @Override
        public void run() {
            if(UserFilter.check() == true) {
                try {
                    String sb = csebase.getServiceUrl();
                    URL mUrl = new URL(sb);

                    HttpURLConnection conn = (HttpURLConnection) mUrl.openConnection();
                    conn.setRequestMethod("POST");
                    conn.setDoInput(true);
                    conn.setDoOutput(true);
                    conn.setUseCaches(false);
                    conn.setInstanceFollowRedirects(false);

                    conn.setRequestProperty("Content-Type", "application/vnd.onem2m-res+xml;ty=2");
                    conn.setRequestProperty("Accept", "application/xml");
                    conn.setRequestProperty("locale", "ko");
                    conn.setRequestProperty("X-M2M-Origin", "S");
                    conn.setRequestProperty("X-M2M-RI", "12345");
                    conn.setRequestProperty("X-M2M-NM", ae.getappName());

                    String reqXml = applicationEntity.makeXML();
                    conn.setRequestProperty("Content-Length", String.valueOf(reqXml.length()));

                    DataOutputStream dos = new DataOutputStream(conn.getOutputStream());
                    dos.write(reqXml.getBytes());
                    dos.flush();
                    dos.close();

                    responseCode = conn.getResponseCode();

                    BufferedReader in = null;
                    String aei = "";
                    if (responseCode == 201) {
                        // Get AEID from Response Data
                        in = new BufferedReader(new InputStreamReader(conn.getInputStream()));

                        String resp = "";
                        String strLine;
                        while ((strLine = in.readLine()) != null) {
                            resp += strLine;
                        }

                        ParseElementXml pxml = new ParseElementXml();
                        aei = pxml.GetElementXml(resp, "aei");
                        ae.setAEid(aei);
                        Log.d(TAG, "Create Get AEID[" + aei + "]");
                        in.close();
                    }
                    if (responseCode != 0) {
                        receiver.getResponseBody(Integer.toString(responseCode));
                    }
                    conn.disconnect();
                } catch (Exception exp) {
                    LOG.log(Level.SEVERE, exp.getMessage());
                }
            }
        }
    }
    /* Retrieve AE-ID */
    class aeRetrieveRequest extends Thread {
        private final Logger LOG = Logger.getLogger(aeCreateRequest.class.getName());
        private IReceived receiver;
        int responseCode=0;

        public aeRetrieveRequest() {
        }
        public void setReceiver(IReceived hanlder) {
            this.receiver = hanlder;
        }

        @Override
        public void run() {
            if(UserFilter.check() == true) {
                try {
                    String sb = csebase.getServiceUrl() + "/" + ae.getappName();
                    URL mUrl = new URL(sb);

                    HttpURLConnection conn = (HttpURLConnection) mUrl.openConnection();
                    conn.setRequestMethod("GET");
                    conn.setDoInput(true);
                    conn.setDoOutput(false
                    );

                    conn.setRequestProperty("Accept", "application/xml");
                    conn.setRequestProperty("X-M2M-RI", "12345");
                    conn.setRequestProperty("X-M2M-Origin", "Sandoroid");
                    conn.setRequestProperty("nmtype", "short");
                    conn.connect();

                    responseCode = conn.getResponseCode();

                    BufferedReader in = null;
                    String aei = "";
                    if (responseCode == 200) {
                        // Get AEID from Response Data
                        in = new BufferedReader(new InputStreamReader(conn.getInputStream()));

                        String resp = "";
                        String strLine;
                        while ((strLine = in.readLine()) != null) {
                            resp += strLine;
                        }

                        ParseElementXml pxml = new ParseElementXml();
                        aei = pxml.GetElementXml(resp, "aei");
                        ae.setAEid(aei);
                        Log.d(TAG, "Retrieve Get AEID[" + aei + "]");
                        in.close();
                    }
                    if (responseCode != 0) {
                        receiver.getResponseBody(Integer.toString(responseCode));
                    }
                    conn.disconnect();
                } catch (Exception exp) {
                    LOG.log(Level.SEVERE, exp.getMessage());
                }
            }
        }
    }
    /* Subscribe Co2 Content Resource */
    class SubscribeResource extends Thread {
        private final Logger LOG = Logger.getLogger(SubscribeResource.class.getName());
        private IReceived receiver;
        private String container_name = targetTAS + "-out"; //change to control container name

        public ContentSubscribeObject subscribeInstance;
        public SubscribeResource() {
            subscribeInstance = new ContentSubscribeObject();
            subscribeInstance.setUrl(csebase.getHost());
            subscribeInstance.setResourceName(ae.getAEid()+"_rn");
            subscribeInstance.setPath(ae.getAEid()+"_sub");
            subscribeInstance.setOrigin_id(ae.getAEid());
        }
        public void setReceiver(IReceived hanlder) { this.receiver = hanlder; }

        @Override
        public void run() {
            //if(UserFilter.check() == true) {
            if(true){
                try {
                    String sb = csebase.getServiceUrl() + "/" + ServiceAEName + "/" + container_name;

                    URL mUrl = new URL(sb);

                    HttpURLConnection conn = (HttpURLConnection) mUrl.openConnection();
                    conn.setRequestMethod("POST");
                    conn.setDoInput(true);
                    conn.setDoOutput(true);
                    conn.setUseCaches(false);
                    conn.setInstanceFollowRedirects(false);

                    conn.setRequestProperty("Accept", "application/xml");
                    conn.setRequestProperty("Content-Type", "application/vnd.onem2m-res+xml; ty=23");
                    conn.setRequestProperty("locale", "ko");
                    conn.setRequestProperty("X-M2M-RI", "12345");
                    conn.setRequestProperty("X-M2M-Origin", ae.getAEid());

                    String reqmqttContent = subscribeInstance.makeXML();
                    conn.setRequestProperty("Content-Length", String.valueOf(reqmqttContent.length()));

                    DataOutputStream dos = new DataOutputStream(conn.getOutputStream());
                    dos.write(reqmqttContent.getBytes());
                    dos.flush();
                    dos.close();

                    BufferedReader in = new BufferedReader(new InputStreamReader(conn.getInputStream()));

                    String resp = "";
                    String strLine = "";
                    while ((strLine = in.readLine()) != null) {
                        resp += strLine;
                    }

                    if (resp != "") {
                        receiver.getResponseBody(resp);
                    }
                    conn.disconnect();

                } catch (Exception exp) {
                    LOG.log(Level.SEVERE, exp.getMessage());
                }
            }
        }
    }

    void msgSendDisplay(final String container, String command){
        ControlRequest req = new ControlRequest(container,command);
        req.setReceiver(new IReceived() {
            public void getResponseBody(final String msg) {
                handler.post(new Runnable() {
                    public void run() {
                        DisplayQuery(container, msg, "LED 제어 명령");
                    }
                });
            }
        });
        req.start();
    }
    String getJsonComponent(final String json, final String key){
        int key_end = json.indexOf("</" + key + ">");
        int key_start = json.indexOf("<" + key + ">");
        if(key_end == -1 || key_start == -1)
            return "no data";
        key_start += (key.length() + 2);    // format length
        return json.substring(key_start, key_end);

    }
    void DisplayQuery(String container, String jstr, String describeHeader){
        String con = getJsonComponent(jstr, "con");

        String display;
        display = "*********** " + describeHeader + "**********\n";
        display += "container\t: " + container + "\n";
        display += "보낸 암호문\t: " + con + "\n";
        display += "전문\n" + jstr;
        textViewData.setText(display);

        display = "*********** " + describeHeader + "**********\n";
        display += "container\t: " + container + "\n";
        display += "암호 복호화 : " + a256.AES_Decode(con); // do something on con //암호
        textViewData2.setText(display);
    }

}
