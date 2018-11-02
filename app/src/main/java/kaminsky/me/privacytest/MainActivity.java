package kaminsky.me.privacytest;

import android.os.Bundle;
import android.support.design.widget.FloatingActionButton;
import android.support.design.widget.Snackbar;
import android.support.v7.app.AppCompatActivity;
import android.support.v7.widget.Toolbar;
import android.view.Menu;
import android.view.MenuItem;
import android.widget.EditText;

import com.google.firebase.analytics.FirebaseAnalytics;

import kaminsky.me.privacytest.utils.PreferencesUtils;
import kaminsky.me.privacytest.utils.PushUtils;

public class MainActivity extends AppCompatActivity {

    private FirebaseAnalytics firebaseAnalytics;

    @Override
    protected void onCreate(Bundle savedInstanceState) {
        super.onCreate(savedInstanceState);
        setContentView(R.layout.activity_main);
        Toolbar toolbar = findViewById(R.id.toolbar);
        setSupportActionBar(toolbar);

        FloatingActionButton fab = findViewById(R.id.fab);
        fab.setOnClickListener(view -> {
            Bundle bundle = new Bundle();
            bundle.putString(FirebaseAnalytics.Param.ITEM_ID, "1");
            bundle.putString(FirebaseAnalytics.Param.ITEM_NAME, "FAB");
            firebaseAnalytics.logEvent(FirebaseAnalytics.Event.SELECT_CONTENT, bundle);

            Snackbar.make(view, "Analytics sent!", Snackbar.LENGTH_LONG).show();
        });

        EditText serverUrl = findViewById(R.id.serverUrl);
        EditText username = findViewById(R.id.username);
        EditText password = findViewById(R.id.password);

        serverUrl.setText(PreferencesUtils.getString(this, PreferencesUtils.KEY_SERVER));
        username.setText(PreferencesUtils.getString(this, PreferencesUtils.KEY_USERNAME));
        password.setText(PreferencesUtils.getString(this, PreferencesUtils.KEY_PASSWORD));

        findViewById(R.id.save).setOnClickListener(v -> {
            PreferencesUtils.setString(getBaseContext(), PreferencesUtils.KEY_SERVER, serverUrl.getText().toString());
            PreferencesUtils.setString(getBaseContext(), PreferencesUtils.KEY_USERNAME, username.getText().toString());
            PreferencesUtils.setString(getBaseContext(), PreferencesUtils.KEY_PASSWORD, password.getText().toString());
        });

        // Obtain the FirebaseAnalytics instance.
        firebaseAnalytics = FirebaseAnalytics.getInstance(this);

        // register to NC
        new Thread(() -> PushUtils.pushRegistrationToServer(MainActivity.this)).start();

    }

    @Override
    public boolean onCreateOptionsMenu(Menu menu) {
        // Inflate the menu; this adds items to the action bar if it is present.
        getMenuInflater().inflate(R.menu.menu_main, menu);
        return true;
    }

    @Override
    public boolean onOptionsItemSelected(MenuItem item) {
        // Handle action bar item clicks here. The action bar will
        // automatically handle clicks on the Home/Up button, so long
        // as you specify a parent activity in AndroidManifest.xml.
        int id = item.getItemId();

        //noinspection SimplifiableIfStatement
        if (id == R.id.action_settings) {
            return true;
        }

        return super.onOptionsItemSelected(item);
    }
}
