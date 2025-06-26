package org.smartdata.test.element;

import com.codeborne.selenide.SelenideElement;

import static com.codeborne.selenide.Selenide.$x;

public interface MenuElement {
    SelenideElement USERNAME = $x("//*[contains(@class, 'systemMenu')]//button[1]//*[contains(@class, 'leftBarMenuItem__label')]");
    SelenideElement DOCUMENTATION_BUTTON = $x("//*[contains(@class, 'systemMenu')]//a[.='Documentation']");
    SelenideElement LOGOUT_BUTTON = $x("//*[contains(@class, 'systemMenu')]//button[.='Log Out']");
    SelenideElement LOGOUT_CONFIRMATION_MODAL = $x("//*[@data-test='dialog-container']");
    SelenideElement LOGOUT_CONFIRMATION_MESSAGE = LOGOUT_CONFIRMATION_MODAL.$x(".//h2");
    SelenideElement LOGOUT_ACCEPT_BUTTON = LOGOUT_CONFIRMATION_MODAL.$x(".//button[@data-test='btn-accept']");
    SelenideElement LOGOUT_REJECT_BUTTON = LOGOUT_CONFIRMATION_MODAL.$x(".//button[@data-test='btn-reject']");
    SelenideElement LOGOUT_CONFIRMATION_MODAL_X_BUTTON = LOGOUT_CONFIRMATION_MODAL.$x(".//button[contains(@class, 'dialog__close')]");
}
