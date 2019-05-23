# Введение

Основное назначение данного документа — описание понятного, простого, применимого на практике руководства по обеспечению безопасности проверки входных данных в приложениях.

# Цель проверки входных данных

Проверка входных данных выполняется для подтверждения ввода в систему только правильно сформированных данных, предотвращая тем самым появление некорректных записей в базе данных, способных вызвать сбои в работе других компонентов. Проверку необходимо проводить на самых ранних этапах обработки, предпочтительно на этапе получения данных от внешнего источника.

Проверку должны проходить все данные от потенциально ненадежных источников, т.е. не только данные, полученные от веб-клиентов, но и данные, передаваемые через внутренние серверы экстрасети от [поставщиков, партнеров, производителей или регуляторов](https://badcyber.com/several-polish-banks-hacked-information-stolen-by-unknown-attackers/), которые могут быть скомпрометированы и использоваться для рассылки вредоносных данных.

Проверка входных данных не должна использоваться в качестве *основного* метода предотвращения [Межсайтовых выполнений сценариев](XSS_(Cross_Site_Scripting)_Prevention_Cheat_Sheet.md), [Внедрений SQL-кода](SQL_Injection_Prevention_Cheat_Sheet.md) и прочих вредоносных действий, которым посвящены соответствующие [памятки](https://www.owasp.org/index.php/OWASP_Cheat_Sheet_Series), но при правильной реализации она может значительно сократить негативные последствия атак.

# Принципы проверки входных данных

Проверка должна осуществляться на **синтаксическом** и **семантическом** уровнях.

**Синтаксическая** проверка должна подтверждать правильность синтаксиса структурированных полей (например, номера социального страхования, даты, обозначения денежных единиц).

**Семантическая** проверка должна подтверждать правильность вводимых *значений* в контексте бизнеса (например, дата начала предшествует дате окончания, цена находится в рамках предполагаемого диапазона).

Атаки необходимо предотвращать на самых ранних стадиях обработки запросов пользователя (злоумышленника). Проверка входных данных может быть использована для обнаружения ввода вредоносных данных, до того как они будут обработаны приложением.

# Реализация проверки входных данных

Проверка входных данных может быть реализована любым программным способом, позволяющим эффективно подтверждать синтаксическую и семантическую правильность, например:

- средствами проверки типов данных, доступными во фреймворках веб-приложений (например, [Django Validators](https://docs.djangoproject.com/en/1.11/ref/validators/) или [Apache Commons Validators](https://commons.apache.org/proper/commons-validator/apidocs/org/apache/commons/validator/package-summary.html#doc.Usage.validator));
- проверкой входных данных на соответствие [JSON Schema](http://json-schema.org/) и [XML Schema (XSD)](https://www.w3schools.com/xml/schema_intro.asp);
- преобразованием типов (например, используя `Integer.parseInt()` на Java, `int()` на Python) со строгой обработкой исключений;
- проверкой минимальных и максимальных значений для числовых параметров и дат, проверкой минимальной и максимальной длины для строк;
- использованием только допустимых значений для небольших наборов строковых параметров (например, дней недели);
- регулярными выражениями для структурированных данных, которые применяются ко всей строке ввода `(^...$)` и **не** содержат подстановочных знаков "любой символ" (например, `.` или `\S`).

## Белые и черные списки

Распространенной ошибкой является использование черных списков для обнаружения потенциально опасных символов и шаблонов (например, апострофов `'`, строк `1=1` или тегов `<script>`), поскольку злоумышленники легко обходят подобные фильтры.

Более того, подобные фильтры зачастую мешают вводу разрешенных данных (например, как в случае с `O'Brian`), в которых символ ' является полностью легитимным. Более подробную информацию по обходу XSS-фильтров можно найти на [этой странице вики](https://www.owasp.org/index.php/XSS_Filter_Evasion_Cheat_Sheet).

Проверка по белому списку вполне подходит для любых полей ввода данных. Белый список точно определяет что РАЗРЕШЕНО, а все остальное, по определению, является запрещенным.

Если данные хорошо структурированы (например, даты, номера социального страхования, почтовые индексы, адреса электронной почты и т. п.), то разработчик может создать очень точный шаблон для проверки подобных данных, как правило основанный на регулярных выражениях.

Если поле ввода данных представляет собой фиксированный набор опций (например, раскрывающийся список или ограниченный список выбора вариантов), то входные данные должны просто совпадать с одним из значений, предлагаемых пользователю.

## Проверка произвольного Юникод-текста

Произвольный текст, особенно содержащий символы Юникода, считается трудным для проверки из-за большого количества символов, которые необходимо включать в белый список.

Также входные данные в форме произвольного текста показывают важность правильного, зависящего от контекста кодирования выходных данных и демонстрируют, что проверка входных данных **не** является основным средством обеспечения защиты от межсайтового выполнения сценариев. Если пользователям по каким-то причинам требуется использовать апостроф `'` или знак "менее чем" `<` в поле комментариев, то приложение должно обеспечивать корректную обработку подобных данных на протяжении всего их жизненного цикла.

Базовые средства проверки данных, вводимых в виде произвольного текста:

- **нормализация** — необходимо обеспечить каноническое кодирование всего текста, а также отсутствие любых недопустимых символов;
- **белые списки категорий символов** — Юникод позволяет создавать белые списки категорий, таких как "десятичные цифры" или "буквы", в которые могут входить не только латинские, но и другие, широко используемые символы, например, арабские, кириллические, китайские, японские или корейские;
- **белые списки отдельных символов** — для случаев когда в именах допускается использование букв и иероглифов, но требуется также разрешить использование апострофа `'` для ирландских имен без разрешения всех знаков (категории) пунктуации.

Ссылки:

- [Проверка данных, вводимых в виде произвольного Юникод-текста, на Python](https://ipsec.pl/python/2017/input-validation-free-form-unicode-text-python.html)

## Регулярные выражения

Создание регулярных выражений является довольно сложным процессом и не рассматривается в данном документе.

В интернете существует множество ресурсов, посвященных написанию регулярных выражений, включая этот [сайт](https://www.regular-expressions.info/) и [репозиторий проверочных регулярных выражений OWASP](https://www.owasp.org/index.php/OWASP_Validation_Regex_Repository).

Таким образом, проверка входных данных должна:

- применяться ко всем входным данным, как минимум;
- определять разрешенный для ввода набор символов;
- определять минимальный и максимальный размер данных (например, `{1,25}` ).

# Примеры регулярных выражений для белых списков

Проверка почтовых индексов США (5 цифр и опционально -4)

```text
^\d{5}(-\d{4})?$
```

Проверка для выбора штата США из раскрывающегося меню

```text
^(AA|AE|AP|AL|AK|AS|AZ|AR|CA|CO|CT|DE|DC|FM|FL|GA|GU|
HI|ID|IL|IN|IA|KS|KY|LA|ME|MH|MD|MA|MI|MN|MS|MO|MT|NE| 
NV|NH|NJ|NM|NY|NC|ND|MP|OH|OK|OR|PW|PA|PR|RI|SC|SD|TN|
TX|UT|VT|VI|VA|WA|WV|WI|WY)$
```

**Пример использования регулярных выражений на Java**

Пример проверки параметра "почтовый индекс" с помощью регулярного выражения:

```java
private static final Pattern zipPattern = Pattern.compile("^\d{5}(-\d{4})?$");

public void doPost( HttpServletRequest request, HttpServletResponse response) {
  try {
      String zipCode = request.getParameter( "zip" );
      if ( !zipPattern.matcher( zipCode ).matches()  {
          throw new YourValidationException( "Improper zipcode format." );
      }
      // делайте здесь, что хотите, если проверка прошла успешно ..
  } catch(YourValidationException e ) {
      response.sendError( response.SC_BAD_REQUEST, e.getMessage() );
  }
}
```

Можно использовать различные бесплатные пакеты, которые содержат уже настроенные проверки по белым спискам. Например:

- [Apache Commons Validator](http://commons.apache.org/proper/commons-validator/)

# Проверки на стороне клиента и на стороне сервера

Помните, что злоумышленники могут обойти любую JavaScript-проверку входных данных, выполняемую на стороне клиента, отключив JavaScript или использовав веб-прокси. Убедитесь, что все проверки входных данных, выполняемые в клиенте, также выполняются на сервере.

# Validating Rich User Content

It is very difficult to validate rich content submitted by a user. For more information, please see the XSS cheatsheet on [Sanitizing HTML Markup with a Library Designed for the Job](Cross_Site_Scripting_Prevention_Cheat_Sheet.md).

# Preventing XSS and Content Security Policy

All user data controlled must be encoded when returned in the html page to prevent the execution of malicious data (e.g. XSS). For example `<script>` would be returned as `&lt;script&gt;`

The type of encoding is specific to the context of the page where the user controlled data is inserted. For example, HTML entity encoding is appropriate for data placed into the HTML body. However, user data placed into a script would need JavaScript specific output encoding.

Detailed information on XSS prevention here: [OWASP XSS Prevention Cheat Sheet](XSS_(Cross_Site_Scripting)_Prevention_Cheat_Sheet.md)

# File Upload Validation

Many websites allow users to upload files, such as a profile picture or more. This section helps provide that feature securely.

Additional information on upload protection here: [File Upload Protection Cheat Sheet](Protect_FileUpload_Against_Malicious_File.md).

## Upload Verification

- Use input validation to ensure the uploaded filename uses an expected extension type.
- Ensure the uploaded file is not larger than a defined maximum file size.
- If the website supports ZIP file upload, do validation check before unzip the file. The check includes the target path, level of compress, estimated unzip size.

## Upload Storage

- Use a new filename to store the file on the OS. Do not use any user controlled text for this filename or for the temporary filename.
- When the file is uploaded to web, it's suggested to rename the file on storage. For example, the uploaded filename is *test.JPG*, rename it to *JAI1287uaisdjhf.JPG* with a random file name. The purpose of doing it to prevent the risks of direct file access and ambigious filename to evalide the filter, such as `test.jpg;.asp or /../../../../../test.jpg`.
- Uploaded files should be analyzed for malicious content (anti-malware, static analysis, etc).
- The file path should not be able to specify by client side. It's decided by server side.

## Public Serving of Uploaded Content

- Ensure uploaded images are served with the correct content-type (e.g. image/jpeg, application/x-xpinstall)

## Beware of "special" files

The upload feature should be using a whitelist approach to only allow specific file types and extensions. However, it is important to be aware of the following file types that, if allowed, could result in security vulnerabilities:
- **crossdomain.xml** / **clientaccesspolicy.xml:** allows cross-domain data loading in Flash, Java and Silverlight. If permitted on sites with authentication this can permit cross-domain data theft and CSRF attacks. Note this can get pretty complicated depending on the specific plugin version in question, so its best to just prohibit files named "crossdomain.xml" or "clientaccesspolicy.xml".
- **.htaccess** and **.htpasswd:** Provides server configuration options on a per-directory basis, and should not be permitted. See [HTACCESS documentation](http://en.wikipedia.org/wiki/Htaccess).
- Web executable script files are suggested not to be allowed such as `aspx, asp, css, swf, xhtml, rhtml, shtml, jsp, js, pl, php, cgi`.

## Upload Verification

- Use image rewriting libraries to verify the image is valid and to strip away extraneous content.
- Set the extension of the stored image to be a valid image extension based on the detected content type of the image from image processing (e.g. do not just trust the header from the upload).
- Ensure the detected content type of the image is within a list of defined image types (jpg, png, etc)

# Email Address Validation

## Email Validation Basics

Many web applications do not treat email addresses correctly due to common misconceptions about what constitutes a valid address. Specifically, it is completely valid to have an mailbox address which:

- Is case sensitive in the local portion of the address (left of the rightmost `@` character).
- Has non-alphanumeric characters in the local-part (including `+` and `@`).
- Has zero or more labels.

At the time of writing, [RFC 5321](https://tools.ietf.org/html/rfc5321) is the current standard defining SMTP and what constitutes a valid mailbox address. Please note, email addresses should be considered to be public data.

Many web applications contain computationally expensive and inaccurate regular expressions that attempt to validate email addresses. Recent changes to the landscape mean that the number of false-negatives will increase, particularly due to:

- Increased popularity of sub-addressing by providers such as Gmail (commonly using `+` as a token in the local-part to affect delivery)
-  New [gTLDs](https://en.wikipedia.org/wiki/Generic_top-level_domain) with long names (many regular expressions check the number and length of each label in the domain)

Following [RFC 5321](https://tools.ietf.org/html/rfc5321), best practice for validating an email address would be to:

- Check for presence of at least one `@` symbol in the address.
- Ensure the local-part is no longer than **64 octets**.
- Ensure the domain is no longer than **255 octets**.
- Ensure the address **is deliverable**.

To ensure an address is deliverable, the only way to check this is to send the user an email and have the user take action to confirm receipt. Beyond confirming that the email address is valid and deliverable, this also provides a positive acknowledgement that the user has access to the mailbox and is likely to be authorized to use it. 

This does not mean that other users cannot access this mailbox, for example when the user makes use of a service that generates a throw away email address.

- Email verification links should only satisfy the requirement of verify email address ownership and should not provide the user with an authenticated session (e.g. the user must still authenticate as normal to access the application).
- Email verification codes must expire after the first use or expire after 8 hours if not used.

## Address Normalization

As the local-part of email addresses are, in fact - case sensitive, it is important to store and compare email addresses correctly. To normalise an email address input, you would convert the domain part ONLY to lowercase.

Unfortunately this does and will make input harder to normalise and correctly match to a users intent. It is reasonable to only accept one unique capitalisation of an otherwise identical address, however in this case it is critical to:

- Store the user-part as provided and verified by user verification.
- Perform comparisons by `lowercase(provided)==lowercase(persisted)`.

# Authors and Primary Editors

Dave Wichers - dave.wichers@aspectsecurity.com