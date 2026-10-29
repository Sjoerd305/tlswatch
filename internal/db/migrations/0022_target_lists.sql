-- Bound target lists before materializing certificates and configuration JSON.
CREATE INDEX targets_expiry ON targets(enabled DESC, CASE WHEN not_after = 0 THEN 1 ELSE 0 END, not_after, name, id);
CREATE INDEX targets_status_id ON targets(status, id);
CREATE INDEX targets_grade_id ON targets(grade, id);
CREATE INDEX targets_pq_id ON targets(pq, id);
