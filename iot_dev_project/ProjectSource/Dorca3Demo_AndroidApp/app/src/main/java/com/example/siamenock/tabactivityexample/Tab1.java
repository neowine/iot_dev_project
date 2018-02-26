package com.example.siamenock.tabactivityexample;

/**
 * Created by siamenock on 2018-02-09.
 */

import android.app.AlertDialog;
import android.support.v4.app.Fragment;
import android.os.Bundle;
import android.view.LayoutInflater;
import android.view.View;
import android.view.ViewGroup;
import android.widget.Button;
import android.widget.EditText;
import android.widget.Toast;


public class Tab1 extends  Fragment implements View.OnClickListener{
    public Button btnSetPassword;
    public EditText etxtPassword;
    public View view;
    @Override
    public View onCreateView(LayoutInflater inflater, ViewGroup container, Bundle savedInstanceState) {
        this.view = inflater.inflate(R.layout.tab1, container, false);

        etxtPassword    = view.findViewById(R.id.etxtPassword);
        btnSetPassword  = view.findViewById(R.id.btnSetPassword);
        btnSetPassword.setOnClickListener(this);
        return view;
    }

    @Override
    public void onClick(View v) {
        switch (v.getId()){
            case R.id.btnSetPassword:
                String newPswd = etxtPassword.getText().toString();
                if(newPswd.length() <= 1)
                    break;

                UserFilter.setGuestPassword(newPswd);

                if(UserFilter.check()){
                    Toast.makeText(this.getActivity(), "new password set! you can control app", Toast.LENGTH_LONG).show();
                    MainActivity main = (MainActivity) this.getActivity();
                    main.tab2.GetAEInfo();  // set basic data of tab2
                    etxtPassword.setText("");
                } else {
                    Toast.makeText(this.getActivity(), "Wrong password. Ask to Neowine staff", Toast.LENGTH_LONG).show();
                }
                break;
        }
    }
}
