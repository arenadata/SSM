package org.smartdata.server.generated.model;

import com.fasterxml.jackson.annotation.JsonProperty;
import com.fasterxml.jackson.annotation.JsonTypeName;
import io.swagger.v3.oas.annotations.media.Schema;
import java.util.Objects;
import javax.annotation.Generated;
import javax.validation.constraints.Min;

/**
 * StateChangeTimeIntervalDto
 */

@JsonTypeName("StateChangeTimeInterval")
@Generated(value = "org.openapitools.codegen.languages.SpringCodegen")
public class StateChangeTimeIntervalDto {

  private Long stateChangedTimeFrom = null;

  private Long stateChangedTimeTo = null;

  public StateChangeTimeIntervalDto stateChangedTimeFrom(Long stateChangedTimeFrom) {
    this.stateChangedTimeFrom = stateChangedTimeFrom;
    return this;
  }

  /**
   * UNIX timestamp (UTC) of the interval start
   * minimum: 0
   * @return stateChangedTimeFrom
  */
  @Min(0L) 
  @Schema(name = "stateChangedTimeFrom", description = "UNIX timestamp (UTC) of the interval start", requiredMode = Schema.RequiredMode.NOT_REQUIRED)
  @JsonProperty("stateChangedTimeFrom")
  public Long getStateChangedTimeFrom() {
    return stateChangedTimeFrom;
  }

  public void setStateChangedTimeFrom(Long stateChangedTimeFrom) {
    this.stateChangedTimeFrom = stateChangedTimeFrom;
  }

  public StateChangeTimeIntervalDto stateChangedTimeTo(Long stateChangedTimeTo) {
    this.stateChangedTimeTo = stateChangedTimeTo;
    return this;
  }

  /**
   * UNIX timestamp (UTC) of the interval end
   * minimum: 0
   * @return stateChangedTimeTo
  */
  @Min(0L) 
  @Schema(name = "stateChangedTimeTo", description = "UNIX timestamp (UTC) of the interval end", requiredMode = Schema.RequiredMode.NOT_REQUIRED)
  @JsonProperty("stateChangedTimeTo")
  public Long getStateChangedTimeTo() {
    return stateChangedTimeTo;
  }

  public void setStateChangedTimeTo(Long stateChangedTimeTo) {
    this.stateChangedTimeTo = stateChangedTimeTo;
  }

  @Override
  public boolean equals(Object o) {
    if (this == o) {
      return true;
    }
    if (o == null || getClass() != o.getClass()) {
      return false;
    }
    StateChangeTimeIntervalDto stateChangeTimeInterval = (StateChangeTimeIntervalDto) o;
    return Objects.equals(this.stateChangedTimeFrom, stateChangeTimeInterval.stateChangedTimeFrom) &&
        Objects.equals(this.stateChangedTimeTo, stateChangeTimeInterval.stateChangedTimeTo);
  }

  @Override
  public int hashCode() {
    return Objects.hash(stateChangedTimeFrom, stateChangedTimeTo);
  }

  @Override
  public String toString() {
    StringBuilder sb = new StringBuilder();
    sb.append("class StateChangeTimeIntervalDto {\n");
    sb.append("    stateChangedTimeFrom: ").append(toIndentedString(stateChangedTimeFrom)).append("\n");
    sb.append("    stateChangedTimeTo: ").append(toIndentedString(stateChangedTimeTo)).append("\n");
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
