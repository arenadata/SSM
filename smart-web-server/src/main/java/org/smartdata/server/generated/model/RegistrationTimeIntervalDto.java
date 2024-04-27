package org.smartdata.server.generated.model;

import com.fasterxml.jackson.annotation.JsonProperty;
import com.fasterxml.jackson.annotation.JsonTypeName;
import io.swagger.v3.oas.annotations.media.Schema;
import java.util.Objects;
import javax.annotation.Generated;
import javax.validation.constraints.Min;

/**
 * RegistrationTimeIntervalDto
 */

@JsonTypeName("RegistrationTimeInterval")
@Generated(value = "org.openapitools.codegen.languages.SpringCodegen")
public class RegistrationTimeIntervalDto {

  private Long registrationTimeFrom = null;

  private Long registrationTimeTo = null;

  public RegistrationTimeIntervalDto registrationTimeFrom(Long registrationTimeFrom) {
    this.registrationTimeFrom = registrationTimeFrom;
    return this;
  }

  /**
   * UNIX timestamp (UTC) of the interval start
   * minimum: 0
   * @return registrationTimeFrom
  */
  @Min(0L) 
  @Schema(name = "registrationTimeFrom", description = "UNIX timestamp (UTC) of the interval start", requiredMode = Schema.RequiredMode.NOT_REQUIRED)
  @JsonProperty("registrationTimeFrom")
  public Long getRegistrationTimeFrom() {
    return registrationTimeFrom;
  }

  public void setRegistrationTimeFrom(Long registrationTimeFrom) {
    this.registrationTimeFrom = registrationTimeFrom;
  }

  public RegistrationTimeIntervalDto registrationTimeTo(Long registrationTimeTo) {
    this.registrationTimeTo = registrationTimeTo;
    return this;
  }

  /**
   * UNIX timestamp (UTC) of the interval end
   * minimum: 0
   * @return registrationTimeTo
  */
  @Min(0L) 
  @Schema(name = "registrationTimeTo", description = "UNIX timestamp (UTC) of the interval end", requiredMode = Schema.RequiredMode.NOT_REQUIRED)
  @JsonProperty("registrationTimeTo")
  public Long getRegistrationTimeTo() {
    return registrationTimeTo;
  }

  public void setRegistrationTimeTo(Long registrationTimeTo) {
    this.registrationTimeTo = registrationTimeTo;
  }

  @Override
  public boolean equals(Object o) {
    if (this == o) {
      return true;
    }
    if (o == null || getClass() != o.getClass()) {
      return false;
    }
    RegistrationTimeIntervalDto registrationTimeInterval = (RegistrationTimeIntervalDto) o;
    return Objects.equals(this.registrationTimeFrom, registrationTimeInterval.registrationTimeFrom) &&
        Objects.equals(this.registrationTimeTo, registrationTimeInterval.registrationTimeTo);
  }

  @Override
  public int hashCode() {
    return Objects.hash(registrationTimeFrom, registrationTimeTo);
  }

  @Override
  public String toString() {
    StringBuilder sb = new StringBuilder();
    sb.append("class RegistrationTimeIntervalDto {\n");
    sb.append("    registrationTimeFrom: ").append(toIndentedString(registrationTimeFrom)).append("\n");
    sb.append("    registrationTimeTo: ").append(toIndentedString(registrationTimeTo)).append("\n");
    sb.append("}");
    return sb.toString();
  }

  /**
   * Convert the given object to string with each line indented by 4 spaces
   * (except the first line).
   */
  private String toIndentedString(Object o) {
    if (o == null) {
      return "null";
    }
    return o.toString().replace("\n", "\n    ");
  }
}
