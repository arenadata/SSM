package org.smartdata.server.generated.model;

import com.fasterxml.jackson.annotation.JsonProperty;
import com.fasterxml.jackson.annotation.JsonTypeName;
import io.swagger.v3.oas.annotations.media.Schema;
import java.util.Objects;
import javax.annotation.Generated;
import javax.validation.constraints.Min;

/**
 * SubmissionTimeIntervalDto
 */

@JsonTypeName("SubmissionTimeInterval")
@Generated(value = "org.openapitools.codegen.languages.SpringCodegen")
public class SubmissionTimeIntervalDto {

  private Long submissionTimeFrom = null;

  private Long submissionTimeTo = null;

  public SubmissionTimeIntervalDto submissionTimeFrom(Long submissionTimeFrom) {
    this.submissionTimeFrom = submissionTimeFrom;
    return this;
  }

  /**
   * UNIX timestamp (UTC) of the interval start
   * minimum: 0
   * @return submissionTimeFrom
  */
  @Min(0L) 
  @Schema(name = "submissionTimeFrom", description = "UNIX timestamp (UTC) of the interval start", requiredMode = Schema.RequiredMode.NOT_REQUIRED)
  @JsonProperty("submissionTimeFrom")
  public Long getSubmissionTimeFrom() {
    return submissionTimeFrom;
  }

  public void setSubmissionTimeFrom(Long submissionTimeFrom) {
    this.submissionTimeFrom = submissionTimeFrom;
  }

  public SubmissionTimeIntervalDto submissionTimeTo(Long submissionTimeTo) {
    this.submissionTimeTo = submissionTimeTo;
    return this;
  }

  /**
   * UNIX timestamp (UTC) of the interval end
   * minimum: 0
   * @return submissionTimeTo
  */
  @Min(0L) 
  @Schema(name = "submissionTimeTo", description = "UNIX timestamp (UTC) of the interval end", requiredMode = Schema.RequiredMode.NOT_REQUIRED)
  @JsonProperty("submissionTimeTo")
  public Long getSubmissionTimeTo() {
    return submissionTimeTo;
  }

  public void setSubmissionTimeTo(Long submissionTimeTo) {
    this.submissionTimeTo = submissionTimeTo;
  }

  @Override
  public boolean equals(Object o) {
    if (this == o) {
      return true;
    }
    if (o == null || getClass() != o.getClass()) {
      return false;
    }
    SubmissionTimeIntervalDto submissionTimeInterval = (SubmissionTimeIntervalDto) o;
    return Objects.equals(this.submissionTimeFrom, submissionTimeInterval.submissionTimeFrom) &&
        Objects.equals(this.submissionTimeTo, submissionTimeInterval.submissionTimeTo);
  }

  @Override
  public int hashCode() {
    return Objects.hash(submissionTimeFrom, submissionTimeTo);
  }

  @Override
  public String toString() {
    StringBuilder sb = new StringBuilder();
    sb.append("class SubmissionTimeIntervalDto {\n");
    sb.append("    submissionTimeFrom: ").append(toIndentedString(submissionTimeFrom)).append("\n");
    sb.append("    submissionTimeTo: ").append(toIndentedString(submissionTimeTo)).append("\n");
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
