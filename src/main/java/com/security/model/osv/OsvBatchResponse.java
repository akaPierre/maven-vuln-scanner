package com.security.model.osv;

import com.google.gson.annotations.SerializedName;

import java.util.List;

/** Response of {@code POST /v1/querybatch}. Only ids are returned; details come from {@code /v1/vulns/{id}}. */
public class OsvBatchResponse {
    public List<Result> results;

    public static class Result {
        public List<VulnRef> vulns;
        @SerializedName("next_page_token")
        public String nextPageToken;
    }

    public static class VulnRef {
        public String id;
    }
}
