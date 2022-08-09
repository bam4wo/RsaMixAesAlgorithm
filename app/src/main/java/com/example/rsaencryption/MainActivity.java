package com.example.rsaencryption;

import android.os.Bundle;
import android.util.Log;
import android.view.View;
import android.widget.Button;
import android.widget.EditText;

import androidx.appcompat.app.AppCompatActivity;

public class MainActivity extends AppCompatActivity {

    private EditText text, encryptResult, decryptResult;
    private Button encrypt, decrypt;
    KeyStoreHelper keyStoreHelper;

    @Override
    protected void onCreate(Bundle savedInstanceState) {
        super.onCreate(savedInstanceState);
        setContentView(R.layout.activity_main);

        text = findViewById(R.id.text);
        encrypt = findViewById(R.id.encrypt);
        decrypt = findViewById(R.id.decrypt);
        encryptResult = findViewById(R.id.result_e);
        decryptResult = findViewById(R.id.result_d);

        keyStoreHelper = new KeyStoreHelper(getApplicationContext());

        encrypt.setOnClickListener(new View.OnClickListener() {
            @Override
            public void onClick(View v) {
                String eResult = keyStoreHelper.encrypt(text.getText().toString());
                encryptResult.setText(eResult);
            }
        });

        decrypt.setOnClickListener(new View.OnClickListener() {
            @Override
            public void onClick(View v) {
                String dResult = keyStoreHelper.decrypt(text.getText().toString());
                decryptResult.setText(dResult);
            }
        });
    }
}