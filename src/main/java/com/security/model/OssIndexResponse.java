package com.security.model;

import com.google.gson.annotations.SerializedName;
import java.util.List;

public class OssIndexResponse {
    @SerializedName("vulnerabilities")
    public List<Vulnerability> vulnerabilities;
}