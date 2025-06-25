import os
import cv2
import requests

API_KEY = "AS73XSsYCjXI0FfhNLQ1"
MODEL_ENDPOINT = "https://detect.roboflow.com/front-view-3/1"

def run_yolo_analysis(image_path):
    with open(image_path, "rb") as img_file:
        response = requests.post(
            f"{MODEL_ENDPOINT}?api_key={API_KEY}",
            files={"file": img_file},
            data={"confidence": "40", "overlap": "30"}
        )

    try:
        result = response.json()
        print("[DEBUG] Roboflow result:", result)
    except Exception as e:
        print("[ERROR] Failed to parse Roboflow response:", e)
        return "", []

    img = cv2.imread(image_path)
    if img is None:
        print("[ERROR] Failed to load image:", image_path)
        return "", []

    detections = []
    for pred in result.get("predictions", []):
        raw_label = pred["class"].lower()
        conf = round(pred["confidence"], 2)

        # Determine type (molar or premolar)
        if "rear" in raw_label:
            tooth_type = "Molar"
        elif "p1" in raw_label or "p2" in raw_label:
            tooth_type = "Premolar"
        else:
            continue  # Ignore non-molar/premolar

        # Determine location (upper or lower)
        if "upper" in raw_label:
            location = "Upper"
        elif "lower" in raw_label:
            location = "Lower"
        else:
            location = ""  # fallback in case not found

        full_label = f"{location} {tooth_type}".strip()  # avoid double space if location missing

        # Bounding box
        x = int(pred["x"] - pred["width"] / 2)
        y = int(pred["y"] - pred["height"] / 2)
        w = int(pred["width"])
        h = int(pred["height"])

        # Draw
        cv2.rectangle(img, (x, y), (x + w, y + h), (0, 255, 0), 2)
        label_text = f"{full_label} ({conf})"
        cv2.putText(img, label_text, (x, y - 5), cv2.FONT_HERSHEY_SIMPLEX, 0.5, (0, 255, 0), 1)

        detections.append({"label": full_label, "confidence": conf})

    result_path = image_path.replace("uploads", "results")
    os.makedirs(os.path.dirname(result_path), exist_ok=True)
    cv2.imwrite(result_path, img)

    return result_path, detections
