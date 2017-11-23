package com.example.apiedra.sslpinning;

import android.app.AlertDialog;
import android.content.DialogInterface;
import android.os.AsyncTask;
import android.util.Log;
import android.widget.ProgressBar;

import javax.net.ssl.HttpsURLConnection;
import java.io.InputStream;
import java.io.StreamTokenizer;
import java.net.URL;

// http://android-developers.blogspot.com/2009/05/painless-threading.html
public class FetchSecretTask extends AsyncTask<Void, Void, Object> {

	@Override
	protected void onPreExecute() {

	}

    @Override
	protected Object doInBackground(Void... params) {

		Object result = null;

		try {

			byte[] secret = null;

            //Getting the keystore
			KeyPinStore keystore = KeyPinStore.getInstance();

            // Tell the URLConnection to use a SocketFactory from our SSLContext
			URL url = new URL( "https://www.random.org/integers/?num=16&min=0&max=255&col=16&base=10&format=plain&rnd=new");
            HttpsURLConnection urlConnection = (HttpsURLConnection)url.openConnection();
            urlConnection.setSSLSocketFactory(keystore.getContext().getSocketFactory());
            InputStream instream = urlConnection.getInputStream();

            // Following OWASP example https://www.owasp.org/index.php/Certificate_and_Public_Key_Pinning
			StreamTokenizer tokenizer = new StreamTokenizer(instream);
			assert (null != tokenizer);

			secret = new byte[16];
			assert (null != secret);

			int idx = 0, token;
			while (idx < secret.length) {
				token = tokenizer.nextToken();
				if (token == StreamTokenizer.TT_EOF)
					break;
				if (token != StreamTokenizer.TT_NUMBER)
					continue;

				secret[idx++] = (byte) tokenizer.nval;
			}

			// Prepare return value
			result = (Object) secret;

		} catch (Exception ex) {

			// Log error
			Log.e("doInBackground", ex.toString());

			// Prepare return value
			result = (Object) ex;
		}

		return result;
	}

	@Override
	protected void onPostExecute(Object result) {



		assert (null != result);
		if (null == result)
			return;

		assert (result instanceof Exception || result instanceof byte[]);
		if (!(result instanceof Exception || result instanceof byte[]))
			return;

		if (result instanceof Exception) {
			ExitWithException((Exception) result);
			return;
		}

		ExitWithSecret((byte[]) result);
	}

	protected void ExitWithException(Exception ex) {

		assert (null != ex);


		System.out.println(ex);

	}

	protected void ExitWithSecret(byte[] secret) {

		assert (null != secret);

		StringBuilder sb = new StringBuilder(secret.length * 3 + 1);
		assert (null != sb);

		for (int i = 0; i < secret.length; i++) {
			sb.append(String.format("%02X ", secret[i]));
			secret[i] = 0;
		}

		System.out.println(sb.toString());
	}
}
