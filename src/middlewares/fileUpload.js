import multer from "multer";
import fs from "fs";

const fileUpload = (uploadDirectory) => {
  if (!fs.existsSync(uploadDirectory)) {
    fs.mkdirSync(uploadDirectory, { recursive: true });
  }
  const storage = multer.diskStorage({
    destination: function (req, file, cb) {
      cb(null, uploadDirectory);
    },
    filename: function (req, file, cb) {
      const parts = file.originalname.split(".");
      const extension = parts.length > 1 ? "." + parts.pop() : "";
      const uniqueSuffix = Date.now() + "-" + Math.round(Math.random() * 1e9);

      cb(null, parts.join("_") + "-" + uniqueSuffix + extension);
    },
  });

  const upload = multer({
    storage: storage,
    limits: { fileSize: 2000000 },
    fileFilter: function (req, file, cb) {
      const validMimeTypes = [
        "image/png",
        "image/jpg",
        "image/jpeg",
        "image/svg",
        "image/svg+xml",
      ];
      if (validMimeTypes.includes(file.mimetype)) {
        cb(null, true);
      } else {
        cb(new Error("Only png, jpg, jpeg, svg format allowed"), false);
      }
    },
  });

  return upload;
};

export default fileUpload;
