package com.example.siamenock.tabactivityexample;

/**
 * Created by siamenock on 2018-02-09.
 */

import android.app.AlertDialog;
import android.os.Bundle;
import android.support.v4.app.Fragment;
import android.text.Editable;
import android.text.TextWatcher;
import android.view.LayoutInflater;
import android.view.View;
import android.view.ViewGroup;
import android.widget.Button;
import android.widget.EditText;


public class Tab3 extends  Fragment implements View.OnClickListener{
    private String ADMIN_COMMAND_NEW_GUEST	  = "create_new_guest";
    private String ADMIN_COMMAND_RESET_GUEST  = "reset_all_guest";
    private String password = "----";

    public Button btnPasswordReset, btnNewPassword;
    public EditText etxtAdminPassword;
    @Override
    public View onCreateView(LayoutInflater inflater, ViewGroup container,
                             Bundle savedInstanceState) {
        View v = inflater.inflate(R.layout.tab3, container, false);

        etxtAdminPassword   = v.findViewById(R.id.etxtAdminPassword);
        btnNewPassword      = v.findViewById(R.id.btnNewPassword);
        btnPasswordReset    = v.findViewById(R.id.btnPasswordReset);

        btnPasswordReset.setOnClickListener(this);
        btnNewPassword  .setOnClickListener(this);

        etxtAdminPassword.addTextChangedListener(new TextWatcher() {
            @Override
            public void beforeTextChanged(CharSequence charSequence, int i, int i1, int i2) {}

            @Override
            public void onTextChanged(CharSequence charSequence, int i, int i1, int i2) {}

            @Override
            public void afterTextChanged(Editable editable) {
                password = etxtAdminPassword.getText().toString();
            }
        });

        return v;
    }
    @Override
    public void onClick(View v){
        String msg = password + " ";
        switch (v.getId()){
            case R.id.btnNewPassword:
                msg += ADMIN_COMMAND_NEW_GUEST;
                break;
            case R.id.btnPasswordReset:
                msg += ADMIN_COMMAND_RESET_GUEST;
                break;
            default:
                return;
        }
        etxtAdminPassword.setText("");
        msg = UserFilter.adminCommand(msg);
        new AlertDialog.Builder(this.getActivity()).setTitle("reply from user filter").setMessage(msg).create().show();
    }
}
