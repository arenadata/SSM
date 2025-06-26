package org.smartdata.test.element;

import com.codeborne.selenide.SelenideElement;

import static com.codeborne.selenide.Selenide.$x;

public interface LoginPageElement {
    SelenideElement USERNAME_FIELD = $x("//input[@name='username']");
    SelenideElement PASSWORD_FIELD = $x("//input[@type='password']");
    SelenideElement SING_IN_BUTTON = $x("//button[@type='submit']");
}
