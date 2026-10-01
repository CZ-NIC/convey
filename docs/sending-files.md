# Sending files

When you split the CSV file into chunks by an e-mail, generated files may be sent to these addresses. Look at the example of an unlocked "send" menu below. You see the list of the recipients, followed by a conditional list of recipients that have been already sent to. Next, an exact e-mail message is printed out, including headers.

In the menu, you may either:

 * **Send** the e-mails
 * **Limit** the messages that are being send at once; if you are not 100 % sure you want to send the the whole message bucket at once.
 * **Edit** the template. The message file will open either in the default GUI or terminal editor. The first line of the template should be `Subject: ...`, followed by a free line. Note that you may include any e-mail headers, such as `Reply-To: ...`, `Cc: ...`, etc. The e-mail will reflect all of them. You may write the message either in plain text or in the HTML.
 * **Choose** which recipients in a checkbox list will receive the message.
 * **Test** sending a message to your own address. You'll be prompted which of the messages should be delivered to you. The e-mail contents possibly modified by a dynamic template is shown just before sending.
 * **Print all e-mails** to a file to have the more granulated control over what is going to be sent.
 * **Toggle file attaching** on and off. A portion of the source file related to this e-mail address might be attached. There are use cases when you do not want the files to be sent with as the body text suits fine.
 * **Toggle paths from the path column attaching** on and off. Files mentioned in a path column and related to this e-amil address might be attached.

```bash
  *** E-mail template ***
Recipient list (1/3): alice@example.com
Already sent (2/3): bob@example.com, cilia@example.com
Attachment: split CSV file attached

Content-Type: text/plain; charset="utf-8"
Content-Transfer-Encoding: 7bit
MIME-Version: 1.0
Subject: My subject
From: me@example.com
Date: Fri, 17 Jan 2020 01:36:28 +0100

Hello,

this is my testing message.

Keen regards

**************************************************
1) Send all e-mails via localhost (1) ←←←←←
l) Limit sending amount to...
e) Edit template...
r) Choose recipients...
t) Send test e-mail...
p) Print e-mails to a file...
a) Attach files (toggle): True
i) Attach paths from path column (toggle): False
x) Go back...
?
```

## Arbitrary e-mail headers, "From" header, GPG signing
In the template, you may specify any e-mail header, such as `Reply-To`, `Cc` or `From`. If `From` is not found, we take `SMTP/email_from_name` config value. If `gnupg` home is found on the default user path, we check if there is a secret key matching the `From` header and if found, e-mail will be GPG-signed. If it is going to be signed, you would see something like `Content-Type: multipart/signed; protocol="application/pgp-signature";` header in the e-mail template preview.

## Dynamic templates
Message is processed with [Jinja2](https://jinja.palletsprojects.com/en/2.10.x/) templating system by default.

Few instruments are included to treat the attachment contents:

* **attachment()** – Prints the attachment contents and prevent it to be attached.
    ```jinja2
    You will find our findings below.

    {{ attachment() }}
    ```
* **row()** – Generate attachment contents fields row by row. Header skipped.
* **amount(count=2)** – Check if the attachment has at least `count` number of lines. Header is not counted. Useful when deciding whether the are single row in the result or multiple.
* **joined(column: int, delimiter=", ")** – Return a column joined by delimiter
* **first_row** – Access first line fields

    Example:
    ```jinja2
    {% if amount() %}
        Here is the complete list of the elements.
        {{ joined(1,"\n") }}
    {% else %}
        Here is the element you had problems with: {{ first_row[1] }}
    {% endif %}
    ```

