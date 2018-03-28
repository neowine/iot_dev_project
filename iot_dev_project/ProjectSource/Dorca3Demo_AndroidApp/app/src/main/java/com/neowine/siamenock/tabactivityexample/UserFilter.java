package com.neowine.siamenock.tabactivityexample;

import java.net.Socket;
import java.io.BufferedReader;
import java.io.IOException;
import java.io.InputStreamReader;
import java.io.PrintWriter;

/**
 * Created by siamenock on 2018-02-21.
 */

public class UserFilter implements Runnable {
    private static String UF_IP    = "18.218.131.138";  // User Filter IP
    private static int    UF_PORT  = 7533;            // User Filter Port
    private static String guest_password  ="not_set";

    private String send, recv;

    public UserFilter(String send_){
        UF_IP   = new String(_Config.UF_IP);
        UF_PORT = _Config.UF_PORT;
        send = send_;
    }

    public static void setGuestPassword(String password){
        guest_password = password;
    }

    public static boolean check(){
        UserFilter uf = new UserFilter(guest_password);
        String msg = uf.send();
        if(msg.indexOf("ok") != -1) return true;
        else                        return false;
    }

    public static String adminCommand(String msg){
        UserFilter uf = new UserFilter(msg);
        return uf.send();
    }


    @Override
    public void run() {
        Socket mSocket = null;
        try {
            // 서버에 요청 보내기
            mSocket = new Socket(UF_IP, UF_PORT);

            // 통로 뚫기
            BufferedReader in   = new BufferedReader(new InputStreamReader(mSocket.getInputStream()));
            PrintWriter out     = new PrintWriter(mSocket.getOutputStream());

            // 메세지 전달
            out.println(send);
            out.flush();

            // 응답 출력
            recv = in.readLine();

        } catch (Exception e) {
            System.out.println(e.getMessage());
        } finally {
            // 소켓 닫기 (연결 끊기)
            try {
                mSocket.close();
            } catch (IOException e) {
                System.out.println(e.getMessage());
            }
        }
    }
    public String send(){
        Thread thread = new Thread(this);
        thread.start();
        try {
            thread.join();
        } catch (InterruptedException e){
            System.out.println(e.getMessage());
        }
        return this.recv;
    }
}
